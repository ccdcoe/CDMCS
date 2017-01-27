# New Dashboard

## Basic Concepts

### Dashboard

* http://docs.grafana.org/reference/dashboard/#json-fields

The Dashboard is where it all comes together. Dashboards can be thought of as of a set of one or more **Panels** organized and arranged into one or more **Rows**.

### Row

* http://docs.grafana.org/reference/dashboard/#panels

A Row is a logical divider within a Dashboard, and is used to group Panels together.

Rows are always 12 “units” wide. These units are automatically scaled dependent on the horizontal resolution of your browser. You can control the relative width of Panels within a row by setting their own width.

### Panel

* http://docs.grafana.org/reference/dashboard/#rows

The Panel is the basic visualization building block in Grafana.

There are currently four Panel types: Graph, Singlestat, Dashlist, Table,and Text.

Panels can be dragged and dropped and rearranged on the Dashboard. They can also be resized. There are a wide variety of styling and formatting options ;)

Each Panel provides a Query Editor **dependent on the Data Source selected in the panel**

#### Query Editor

The Query Editor exposes capabilities of your Data Source and allows you to query the metrics that it contains.

Use the Query Editor to build one or more queries (for one or more series) in your time series database.

------

* JSON http://docs.grafana.org/reference/dashboard/#dashboard-json
* API http://docs.grafana.org/http_api/dashboard/#create-update-dashboard
