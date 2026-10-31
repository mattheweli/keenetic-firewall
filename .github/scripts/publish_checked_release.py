#!/usr/bin/env python3
"""Publish exactly the approved draft/assets, without rebuilding release files."""
from pathlib import Path
import hashlib,json,os,subprocess,tempfile

def require(value,message):
 if not value:raise RuntimeError(message)

def gh(*args,payload=None):
 r=subprocess.run(['gh',*args],input=json.dumps(payload) if payload is not None else None,text=True,capture_output=True,timeout=180)
 require(r.returncode==0,'GitHub operation failed: '+r.stderr)
 return r.stdout

def api(path,payload=None):
 args=['api',path]
 if payload is not None:args+=['--method','PATCH','--input','-']
 return json.loads(gh(*args,payload=payload))

def validate_release(plan,release):
 require(release['id']==plan['release_id'],'Release ID changed')
 require(release['tag_name']==plan['tag'],'Release tag changed')
 require(release['target_commitish']==plan['target'],'Release target changed')
 require(release['prerelease'] is False,'Prerelease is not eligible')
 actual={a['name']:a for a in release['assets']}
 require(len(actual)==len(release['assets']) and set(actual)==set(plan['assets']),'Release asset set changed')
 for name,expected in plan['assets'].items():
  a=actual[name]
  require(a['state']=='uploaded' and a['size']==expected['size'] and a['digest']==expected['digest'],'Release asset changed: '+name)

def tag_target(prefix,tag):
 refs=api(prefix+'/git/matching-refs/tags/'+tag)
 exact=[r for r in refs if r['ref']=='refs/tags/'+tag]
 require(len(exact)<=1,'Ambiguous release tag')
 if not exact:return None
 obj=exact[0]['object']
 for _ in range(5):
  if obj['type']=='commit':return obj['sha']
  require(obj['type']=='tag','Unexpected tag object')
  obj=api(prefix+'/git/tags/'+obj['sha'])['object']
 raise RuntimeError('Excessive annotated tag nesting')

def main():
 plan=json.loads(Path('.github/release-publication.json').read_text());repo=plan['repository'];prefix='repos/'+repo
 require(os.environ.get('GITHUB_REPOSITORY')==repo,'Wrong publication repository')
 require(os.environ.get('GITHUB_REF')==plan['operation_ref'],'Wrong publication branch')
 run=api(prefix+'/actions/runs/'+str(plan['validated_run']))
 require(run['head_sha']==plan['target'] and run['status']=='completed' and run['conclusion']=='success','Approved build did not pass')
 pr=api(prefix+'/pulls/'+str(plan['pr']))
 require(pr['head']['sha']==plan['target'] and pr['base']['ref']=='main','PR no longer matches the approved source')
 release=api(prefix+'/releases/'+str(plan['release_id']));validate_release(plan,release)
 existing_tag=tag_target(prefix,plan['tag'])
 require(existing_tag is None or existing_tag==plan['target'],'Existing tag points to different code')
 # Download the existing assets; no archive is regenerated or replaced.
 with tempfile.TemporaryDirectory() as td:
  gh('release','download',plan['tag'],'--repo',repo,'--dir',td)
  downloaded={p.name:p for p in Path(td).iterdir()}
  require(set(downloaded)==set(plan['assets']),'Downloaded asset set mismatch')
  for name,p in downloaded.items():
   require(p.is_file() and 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()==plan['assets'][name]['digest'],'Downloaded asset checksum mismatch: '+name)
   if name.endswith('.sha256'):
    archive=name[:-7];require(archive in downloaded,'Missing archive for checksum')
    require(p.read_text().strip()==plan['assets'][archive]['digest'][7:]+'  '+archive,'Invalid checksum sidecar')
 if release['draft']:
  body=(release.get('body') or '').replace('This prepared release is a draft; no router reboot or public deployment is claimed.','Automated validation uses isolated fixtures. Physical-router reboot and live notification delivery were not independently verified for this release.')
  release=api(prefix+'/releases/'+str(plan['release_id']),{'draft':False,'prerelease':False,'make_latest':'true','body':body})
 validate_release(plan,release)
 require(release['draft'] is False and release['published_at'],'Release was not published')
 require(tag_target(prefix,plan['tag'])==plan['target'],'Published tag target mismatch')
 latest=api(prefix+'/releases/latest');require(latest['id']==plan['release_id'],'Stable release is not latest')
 if pr['draft']:
  gh('pr','ready',str(plan['pr']),'--repo',repo)
  require(api(prefix+'/pulls/'+str(plan['pr']))['draft'] is False,'PR still marked as draft')
 if plan.get('merge'):
  pr=api(prefix+'/pulls/'+str(plan['pr']))
  if not pr['merged']:
   require(api(prefix+'/git/ref/heads/main')['object']['sha']==plan['base_commit'],'Main advanced before approved merge')
   merged=json.loads(gh('api',prefix+'/pulls/'+str(plan['pr'])+'/merge','--method','PUT','--input','-',payload={'sha':plan['target'],'merge_method':'merge','commit_title':'Merge approved '+plan['tag']+' stable release'}))
   require(merged.get('merged') is True,'Approved PR merge failed')
   pr=api(prefix+'/pulls/'+str(plan['pr']))
  require(pr['merged'] is True and api(prefix+'/git/commits/'+pr['merge_commit_sha'])['tree']['sha']==plan['source_tree'],'Merged tree differs from the approved release')
  print('Merged verified source: '+pr['merge_commit_sha'])
 print('Published and verified: '+release['html_url'])

if __name__=='__main__':main()
