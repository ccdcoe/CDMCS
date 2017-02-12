# tasks

* Create following dashboards:
  1. Load1, CPU usage, memory usage, disk usage, IOwait
    * for each host, create a line for maximum values per 5 minute interval
  2. Network interface usage per host and interface.
    * Display the result is megabits per second.
    * Y axis tag to reflect that
  3. Load1, load5 and load15 measurements on single graph.
    * Ensure that a graph is generated dynamically for each host
    * Create a threshold for visualizing critical load
* Create a playlist which rotates these dashboards in one minute interval
* Challenge
  * Create a single graph displaying disk usage.
    * Single host, per host grouping, graph for each - your choice
    * On that same graph, display holt-winters prediction for that stat
    * When will disk usage exceed 100%?
