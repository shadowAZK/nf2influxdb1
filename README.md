# nf2influxdb1

Simple server converter of NetFlow version 5 packet stream to InfluxDB version 1 format. 
A little old, but still in use. Found similar projects but they were CPU intensive.

## Description
This project can be used as a base for simple converter/analyser of NetFlow information
for insertion into InfluxDB. After that the information can be visualised in ex. Grafana.

## Getting Started

### Dependencies

* OS: Linux 
* Python3 libraries
    * netflow
    * influxdb
    * geoip2

### Installing

* Download app code from [@repo](https://github.com/shadowAZK/nf2influxdb1)
* Customise code parameters(default below):
    * nfListenIP = '0.0.0.0'
    * nfListenPort = 2055
    * influxSendIP = 'localhost'
    * influxSendPort = 8086
    * influxSendUsername = ''
    * influxSendPassword = ''
    * influxSendDb = 'netflowDB'
    * influxSendMeasurement = 'sum_proto' 
* Download GeoIP Databases from [@MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and put them in db/:
    * GeoLite2-Country.mmdb
    * GeoLite2-City.mmdb

### Executing program
* Run the script:
```
python3 nf2influxdb1.py
```

## Help

ToDo

## Authors
ShadowAZK
[@WWW](https://shadow.waw.pl/)
[@email](email://shadow@list.pl)

## Version History

* 0.1
    * Initial Release - primary functions works most of the time, code security and exception handling nearly not existing.   

## License

This project is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) License - see the LICENSE.md file for details

## Acknowledgments

* Inspiration on similar project, but that one is more extensive [javadmohebbi](https://github.com/javadmohebbi), at this moment Grafana dashboards entirely based on that project.
