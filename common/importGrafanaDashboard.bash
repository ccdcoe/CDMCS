
curl -s -XPOST --user admin:admin 10.2.44.1:3000/api/dashboards/import -H "Content-Type: application/json" -d '
{
    "dashboard": {
        "__inputs": [{
            "name": "DS_TELEGRAF",
            "label": "telegraf",
            "description": "",
            "type": "datasource",
            "pluginId": "influxdb",
            "pluginName": "InfluxDB"
        }],
        "__requires": [{
            "type": "grafana",
            "id": "grafana",
            "name": "Grafana",
            "version": "4.2.0"
        }, {
            "type": "panel",
            "id": "graph",
            "name": "Graph",
            "version": ""
        }, {
            "type": "datasource",
            "id": "influxdb",
            "name": "InfluxDB",
            "version": "1.0.0"
        }],
        "annotations": {
            "list": []
        },
        "editable": true,
        "gnetId": null,
        "graphTooltip": 1,
        "hideControls": false,
        "id": null,
        "links": [],
        "refresh": false,
        "rows": [{
            "collapse": false,
            "height": "250px",
            "panels": [{
                "aliasColors": {},
                "bars": false,
                "datasource": "${DS_TELEGRAF}",
                "fill": 1,
                "id": 1,
                "legend": {
                    "alignAsTable": true,
                    "avg": true,
                    "current": true,
                    "max": true,
                    "min": true,
                    "rightSide": true,
                    "show": true,
                    "total": false,
                    "values": true
                },
                "lines": true,
                "linewidth": 1,
                "links": [],
                "nullPointMode": "null",
                "percentage": false,
                "pointradius": 5,
                "points": false,
                "renderer": "flot",
                "seriesOverrides": [],
                "span": 12,
                "stack": false,
                "steppedLine": false,
                "targets": [{
                    "alias": "$tag_host",
                    "dsType": "influxdb",
                    "groupBy": [{
                        "params": ["$interval"],
                        "type": "time"
                    }, {
                        "params": ["host"],
                        "type": "tag"
                    }, {
                        "params": ["null"],
                        "type": "fill"
                    }],
                    "measurement": "system",
                    "policy": "default",
                    "refId": "A",
                    "resultFormat": "time_series",
                    "select": [
                        [{
                            "params": ["load1"],
                            "type": "field"
                        }, {
                            "params": [],
                            "type": "mean"
                        }]
                    ],
                    "tags": []
                }],
                "thresholds": [],
                "timeFrom": null,
                "timeShift": null,
                "title": "load1",
                "tooltip": {
                    "shared": true,
                    "sort": 0,
                    "value_type": "individual"
                },
                "type": "graph",
                "xaxis": {
                    "mode": "time",
                    "name": null,
                    "show": true,
                    "values": []
                },
                "yaxes": [{
                    "format": "short",
                    "label": null,
                    "logBase": 1,
                    "max": null,
                    "min": null,
                    "show": true
                }, {
                    "format": "short",
                    "label": null,
                    "logBase": 1,
                    "max": null,
                    "min": null,
                    "show": true
                }]
            }],
            "repeat": null,
            "repeatIteration": null,
            "repeatRowId": null,
            "showTitle": false,
            "title": "Dashboard Row",
            "titleSize": "h6"
        }, {
            "collapse": false,
            "height": 250,
            "panels": [{
                "aliasColors": {},
                "bars": false,
                "datasource": "${DS_TELEGRAF}",
                "fill": 1,
                "id": 2,
                "legend": {
                    "alignAsTable": true,
                    "avg": true,
                    "current": true,
                    "max": true,
                    "min": true,
                    "rightSide": true,
                    "show": true,
                    "total": false,
                    "values": true
                },
                "lines": true,
                "linewidth": 1,
                "links": [],
                "nullPointMode": "null",
                "percentage": false,
                "pointradius": 5,
                "points": false,
                "renderer": "flot",
                "seriesOverrides": [],
                "span": 12,
                "stack": false,
                "steppedLine": false,
                "targets": [{
                    "alias": "$tag_host $tag_interface recv",
                    "dsType": "influxdb",
                    "groupBy": [{
                        "params": ["$interval"],
                        "type": "time"
                    }, {
                        "params": ["host"],
                        "type": "tag"
                    }, {
                        "params": ["interface"],
                        "type": "tag"
                    }, {
                        "params": ["null"],
                        "type": "fill"
                    }],
                    "measurement": "net",
                    "policy": "default",
                    "refId": "A",
                    "resultFormat": "time_series",
                    "select": [
                        [{
                            "params": ["bytes_recv"],
                            "type": "field"
                        }, {
                            "params": [],
                            "type": "last"
                        }, {
                            "params": ["10s"],
                            "type": "non_negative_derivative"
                        }]
                    ],
                    "tags": []
                }, {
                    "alias": "$tag_host $tag_interface sent",
                    "dsType": "influxdb",
                    "groupBy": [{
                        "params": ["$interval"],
                        "type": "time"
                    }, {
                        "params": ["host"],
                        "type": "tag"
                    }, {
                        "params": ["interface"],
                        "type": "tag"
                    }, {
                        "params": ["null"],
                        "type": "fill"
                    }],
                    "measurement": "net",
                    "policy": "default",
                    "refId": "B",
                    "resultFormat": "time_series",
                    "select": [
                        [{
                            "params": ["bytes_sent"],
                            "type": "field"
                        }, {
                            "params": [],
                            "type": "last"
                        }, {
                            "params": ["10s"],
                            "type": "non_negative_derivative"
                        }]
                    ],
                    "tags": []
                }],
                "thresholds": [],
                "timeFrom": null,
                "timeShift": null,
                "title": "net",
                "tooltip": {
                    "shared": true,
                    "sort": 0,
                    "value_type": "individual"
                },
                "type": "graph",
                "xaxis": {
                    "mode": "time",
                    "name": null,
                    "show": true,
                    "values": []
                },
                "yaxes": [{
                    "format": "short",
                    "label": null,
                    "logBase": 1,
                    "max": null,
                    "min": null,
                    "show": true
                }, {
                    "format": "short",
                    "label": null,
                    "logBase": 1,
                    "max": null,
                    "min": null,
                    "show": true
                }]
            }],
            "repeat": null,
            "repeatIteration": null,
            "repeatRowId": null,
            "showTitle": false,
            "title": "Dashboard Row",
            "titleSize": "h6"
        }],
        "schemaVersion": 14,
        "style": "dark",
        "tags": [],
        "templating": {
            "list": []
        },
        "time": {
            "from": "now-24h",
            "to": "now"
        },
        "timepicker": {
            "refresh_intervals": ["5s", "10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d"],
            "time_options": ["5m", "15m", "1h", "6h", "12h", "24h", "2d", "7d", "30d"]
        },
        "timezone": "browser",
        "title": "overview",
        "version": 2
    },
    "overwrite": true,
    "inputs": [{
        "name": "DS_TELEGRAF",
        "type": "datasource",
        "pluginId": "influxdb",
        "value": "telegraf"
    }]
}
'
