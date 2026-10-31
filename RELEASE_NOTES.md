# keenetic-firewall 4.0.10

- Display Top Threats & Targets in three columns at desktop viewport widths of 1,200px and above, two columns from 800px, and one column on smaller screens. Apply the same layout to all four periods and both rows of tables.
- Give each table an equal scroll viewport, up to 600px and capped at 65% of viewport height. Keep column headings sticky while independently scrolling each table.
- Wrap full IPv6 addresses, source/subnet details, port badges and organization names instead of forcing wide tables or truncating metadata. Keep CNT/HITS numbers intact on one line and retain Details and +N port controls.
- Add a real Chromium layout check across eight viewport widths, two densities and four periods, including long IPv6 addresses, large counters, wrapping, internal scrolling and sticky headers.

Package 2.0.21; Firewall component 4.0.10; Firewall dashboard 2.0.3. KeenTool manager remains 2.0.12, Main Dashboard 2.0.4, Stats 4.0.2 and hook 3.0.1. Filtering policy, databases, credentials and schedules are unchanged.

Install using coordinated KeenTool package 2.0.21 (manager remains 2.0.12), then reload the Firewall page.
