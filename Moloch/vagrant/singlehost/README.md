# Moloch & Suricata (in single box)

* **Moloch** is full packet capturing, indexing, and database system.
 * MOLOCH is not IDS
 * WISE is helper service to check external knowledge before saving session indax data
* **Suricata** is checking traffic against described know threats (rules) and creates and logs alert if match is found
 * Suricata is IDS (and NSM tool).
 *  EveBox is a web based Suricata "eve log" event, including alerts, viewer
  * Evebox has API to query alerts

WISE plugin **[source.suricata.js](source.suricata.js)** *"connects"* Moloch session to Suricata alert.

....
