/*
 *  Copyright (C) 2016 PhracturedBlue
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ESP8266MQTTMesh.h"


#include "Base64.h"
#include "eboot_command.h"

#include <limits.h>
extern "C" {
  #include "user_interface.h"
  extern uint32_t _SPIFFS_start;
}

enum {
    NETWORK_LAST_INDEX = -2,
    NETWORK_MESH_NODE  = -1,
};

//Define GATEWAY_ID to the value of ESP.getChipId() in order to prevent only a specific node from connecting via MQTT
#ifdef GATEWAY_ID
    #define IS_GATEWAY (ESP.getChipId() == GATEWAY_ID)
#else
    #define IS_GATEWAY (1)
#endif

#ifndef STAILQ_NEXT //HAS_ESP8266_24
#define NEXT_STATION(station_list)  station_list->next
#else
#define NEXT_STATION(station_list) STAILQ_NEXT(station_list, next)
#endif

//#define EMMDBG_LEVEL (EMMDBG_WIFI | EMMDBG_MQTT | EMMDBG_OTA)
#ifndef EMMDBG_LEVEL
  //#define EMMDBG_LEVEL EMMDBG_ALL_EXTRA
  #define EMMDBG_LEVEL EMMDBG_NONE
  //#define EMMDBG_LEVEL EMMDBG_MQTT_EXTRA
#endif

#define dbgPrintln(lvl, msg) if (((lvl) & (EMMDBG_LEVEL)) == (lvl)) Serial.println("[" + String(__FUNCTION__) + "] " + msg)
size_t strlcat (char *dst, const char *src, size_t len) {
    size_t slen = strlen(dst);
    return strlcpy(dst + slen, src, len - slen);
}

ESP8266MQTTMesh::ESP8266MQTTMesh(const char **networks,
                                const char *network_password,
                                const char *firmware_ver,
                                int firmware_id,
                                const char *mesh_password,
                                const char *base_ssid,
                                int mesh_port,
#if ASYNC_TCP_SSL_ENABLED
                                bool mqtt_secure,
                                const uint8_t *mqtt_fingerprint,
                                bool mesh_secure,
#endif
                                const char *inTopic,
                                const char *outTopic
                    ) :
        networks(networks),
        network_password(network_password),
        firmware_id(firmware_id),
        firmware_ver(firmware_ver),
        mesh_password(mesh_password),
        base_ssid(base_ssid),
        mesh_port(mesh_port),
#if ASYNC_TCP_SSL_ENABLED
        mqtt_secure(mqtt_secure),
        mqtt_fingerprint(mqtt_fingerprint),
        mesh_secure(mesh_secure),
#endif
        inTopic(inTopic),
        outTopic(outTopic),
        espServer(mesh_port)
{

    espClient[0] = new AsyncClient();
    mySSID[0] = 0;
}

ESP8266MQTTMesh::ESP8266MQTTMesh(unsigned int firmware_id,
                                const char *firmware_ver,
                                 const char **networks,
                                 const char *network_password,
                                 const char *mesh_password,
                                 const char *base_ssid,
                                 const char *inTopic,
                                 const char *outTopic
#if ASYNC_TCP_SSL_ENABLED
                                 , bool mqtt_secure,
                                 const uint8_t *mqtt_fingerprint,
                                 bool mesh_secure
#endif
                                 ) :
    ESP8266MQTTMesh(networks,
					network_password,
                    firmware_ver,
					firmware_id,
                    mesh_password,
					base_ssid, mesh_port,
#if ASYNC_TCP_SSL_ENABLED
                    mqtt_secure,
					mqtt_fingerprint,
					mesh_secure,
#endif
                    inTopic,
					outTopic)
					{}

void ESP8266MQTTMesh::setCallback(std::function<void(const char *topic, const char *msg)> _callback) {
    callback = _callback;
}

void ESP8266MQTTMesh::begin() {
    int len = strlen(inTopic);
    if (len > 16) {
        dbgPrintln(EMMDBG_MSG, "Max inTopicLen == 16");
        die();
    }
    if (inTopic[len-1] != '/') {
        dbgPrintln(EMMDBG_MSG, "inTopic must end with '/'");
        die();
    }
    len = strlen(outTopic);
    if (len > 16) {
        dbgPrintln(EMMDBG_MSG, "Max outTopicLen == 16");
        die();
    }
    if (outTopic[len-1] != '/') {
        dbgPrintln(EMMDBG_MSG, "outTopic must end with '/'");
        die();
    }

    dbgPrintln(EMMDBG_MSG_EXTRA, "Starting Firmware " + String(firmware_id, HEX) + " : " + String(firmware_ver));

    if (! SPIFFS.begin()) {
      dbgPrintln(EMMDBG_MSG_EXTRA, "Formatting FS");
      SPIFFS.format();
      if (! SPIFFS.begin()) {
        dbgPrintln(EMMDBG_MSG, "Failed to format FS");
        die();
      }
    }
    Dir dir = SPIFFS.openDir("/bssid/");
    while(dir.next()) {
      dbgPrintln(EMMDBG_FS, " ==> '" + dir.fileName() + "'");
    }
    WiFi.disconnect();
    // In the ESP8266 2.3.0 API, there seems to be a bug which prevents a node configured as
    // WIFI_AP_STA from openning a TCP connection to it's gateway if the gateway is also
    // in WIFI_AP_STA
    WiFi.mode(WIFI_STA);

    wifiConnectHandler     = WiFi.onStationModeGotIP(            [this] (const WiFiEventStationModeGotIP& e) {                this->onWifiConnect(e);    });
    wifiDisconnectHandler  = WiFi.onStationModeDisconnected(     [this] (const WiFiEventStationModeDisconnected& e) {         this->onWifiDisconnect(e); });
    //wifiDHCPTimeoutHandler = WiFi.onStationModeDHCPTimeout(      [this] () {                                                  this->onDHCPTimeout();     });
    wifiAPConnectHandler   = WiFi.onSoftAPModeStationConnected(  [this] (const WiFiEventSoftAPModeStationConnected& ip) {     this->onAPConnect(ip);     });
    wifiAPDisconnectHandler= WiFi.onSoftAPModeStationDisconnected([this] (const WiFiEventSoftAPModeStationDisconnected& ip) { this->onAPDisconnect(ip);  });

    espClient[0]->onConnect(   [this](void * arg, AsyncClient *c)                           { this->onConnect(c);         }, this);
    espClient[0]->onDisconnect([this](void * arg, AsyncClient *c)                           { this->onDisconnect(c);      }, this);
    espClient[0]->onPoll(      [this](void * arg, AsyncClient *c)                           { this->onPoll(c);            }, this);
    espClient[0]->onError(     [this](void * arg, AsyncClient *c, int8_t error)             { this->onError(c, error);    }, this);
    espClient[0]->onAck(       [this](void * arg, AsyncClient *c, size_t len, uint32_t time){ this->onAck(c, len, time);  }, this);
    espClient[0]->onTimeout(   [this](void * arg, AsyncClient *c, uint32_t time)            { this->onTimeout(c, time);   }, this);
    espClient[0]->onData(      [this](void * arg, AsyncClient *c, void* data, size_t len)   { this->onData(c, data, len); }, this);

    espServer.onClient(     [this](void * arg, AsyncClient *c){ this->onClient(c);  }, this);
    //<changed bt HC>espServer.setNoDelay(false);

#if ASYNC_TCP_SSL_ENABLED
    espServer.onSslFileRequest([this](void * arg, const char *filename, uint8_t **buf) -> int { return this->onSslFileRequest(filename, buf); }, this);
    if (mesh_secure) {
        dbgPrintln(EMMDBG_WIFI, "Starting secure server");
        espServer.beginSecure("/ssl/server.cer","/ssl/server.key",NULL);
    } else
#endif
    espServer.begin();

    mqttClient.onConnect(    [this] (bool sessionPresent)                    { this->onMqttConnect(sessionPresent); });
    mqttClient.onDisconnect( [this] (AsyncMqttClientDisconnectReason reason) { this->onMqttDisconnect(reason); });
    mqttClient.onSubscribe(  [this] (uint16_t packetId, uint8_t qos)         { this->onMqttSubscribe(packetId, qos); });
    mqttClient.onUnsubscribe([this] (uint16_t packetId)                      { this->onMqttUnsubscribe(packetId); });
    mqttClient.onMessage(    [this] (char* topic, char* payload, AsyncMqttClientMessageProperties properties, size_t len, size_t index, size_t total)
                                                                             { this->onMqttMessage(topic, payload, properties, len, index, total); });
    mqttClient.onPublish(    [this] (uint16_t packetId)                      { this->onMqttPublish(packetId); });

    Settings::load(settings);

    String strMqttServer = settings.mqttServer();
    if (strMqttServer.length() > 0) {
      int Parts[4] = {0,0,0,0};
      int Part = 0;
      for ( int i=0; i<strMqttServer.length(); i++ )
      {
      	char c = strMqttServer[i];
      	if ( c == '.' )
      	{
      		Part++;
      		continue;
      	}
      	Parts[Part] *= 10;
      	Parts[Part] += c - '0';
      }

      IPAddress mqttServer( Parts[0], Parts[1], Parts[2], Parts[3] );
      mqttClient.setServer(mqttServer, settings.mqttPort());

      if (settings.mqttUsername.length() > 0 || settings.mqttPassword.length() > 0)
          mqttClient.setCredentials(settings.mqttUsername.c_str(), settings.mqttPassword.c_str());
    }

#if ASYNC_TCP_SSL_ENABLED
    mqttClient.setSecure(mqtt_secure);
    if (mqtt_fingerprint) {
        mqttClient.addServerFingerprint(mqtt_fingerprint);
    }
#endif
    //mqttClient.setCallback([this] (char* topic, byte* payload, unsigned int length) { this->mqtt_callback(topic, payload, length); });

    dbgPrintln(EMMDBG_WIFI_EXTRA, WiFi.status());
    dbgPrintln(EMMDBG_MSG_EXTRA, "Setup Complete");
    ap_idx = LAST_AP;
    retry_connect = 1;
    connect();

    //<Added by HC>
    schedule_check_ack(10.0);
    //</Added by HC>
}

bool ESP8266MQTTMesh::isAPConnected(uint8 *mac) {
    struct station_info *station_list = wifi_softap_get_station_info();
    while (station_list != NULL) {
        if(memcmp(mac, station_list->bssid, 6) == 0) {
            return true;
        }
        station_list = NEXT_STATION(station_list);
    }
    return false;
}

void ESP8266MQTTMesh::getMAC(IPAddress ip, uint8 *mac) {
    struct station_info *station_list = wifi_softap_get_station_info();
    while (station_list != NULL) {
        if ((&station_list->ip)->addr == ip) {
            memcpy(mac, station_list->bssid, 6);
            return;
        }
        station_list = NEXT_STATION(station_list);
    }
    memset(mac, 0, 6);
}

bool ESP8266MQTTMesh::connected() {
    return wifiConnected() && ((meshConnect && espClient[0] && espClient[0]->connected()) || mqttClient.connected());
}

bool ESP8266MQTTMesh::match_bssid(const char *bssid) {
    char filename[32];
    dbgPrintln(EMMDBG_WIFI, "Trying to match known BSSIDs for " + String(bssid));
    strlcpy(filename, "/bssid/", sizeof(filename));
    strlcat(filename, bssid, sizeof(filename));
    return SPIFFS.exists(filename);
}

void ESP8266MQTTMesh::scan() {
    //Need to rescan
    if (! scanning) {
        for(int i = 0; i < LAST_AP; i++) {
            ap[i].rssi = -99999;
            ap[i].ssid_idx = NETWORK_LAST_INDEX;
        }
        ap_idx = 0;
        WiFi.disconnect();
        //<added by HC>
        if (!standAloneAP) {
            WiFi.mode(WIFI_STA);
        }
        //</added by HC>
        dbgPrintln(EMMDBG_WIFI, "Scanning for networks");
        WiFi.scanDelete();
        WiFi.scanNetworks(true,true);
        scanning = true;
    }
    //<added by HC>
    int knownNetworksFound = 0;
    //</added by HC>
    int numberOfNetworksFound = WiFi.scanComplete();
    if (numberOfNetworksFound < 0) {
        return;
    }
    scanning = false;
    dbgPrintln(EMMDBG_WIFI, "Found: " + String(numberOfNetworksFound));
    int ssid_idx;
    for(int i = 0; i < numberOfNetworksFound; i++) {
        bool found = false;
        char ssid[32];
        int network_idx = NETWORK_MESH_NODE;
        strlcpy(ssid, WiFi.SSID(i).c_str(), sizeof(ssid));
        dbgPrintln(EMMDBG_WIFI, "Found SSID: '" + String(ssid) + "' BSSID '" + WiFi.BSSIDstr(i) + "'");
        if (ssid[0] != 0) {
            if (IS_GATEWAY) {
            for(network_idx = 0; networks[network_idx] != NULL && networks[network_idx][0] != 0; network_idx++) {
                if(strcmp(ssid, networks[network_idx]) == 0) {
                    dbgPrintln(EMMDBG_WIFI, "Matched");
                    //<added by HC>
                    knownNetworksFound += 1;
                    //</added by HC>
                    found = true;
                    break;
                }
            }
            }
            if(! found) {
                dbgPrintln(EMMDBG_WIFI, "Did not match SSID list");
                continue;
            }
            if (0) {
                FSInfo fs_info;
                SPIFFS.info(fs_info);
                if (fs_info.usedBytes !=0) {
                    dbgPrintln(EMMDBG_WIFI, "Trying to match known BSSIDs for " + WiFi.BSSIDstr(i));
                    if (! match_bssid(WiFi.BSSIDstr(i).c_str())) {
                        dbgPrintln(EMMDBG_WIFI, "Failed to match BSSID");
                        continue;
                    } else {
                        //<added by HC>
                        knownNetworksFound += 1;
                        //</added by HC>
                    }
                }
            }
        } else {

            //<added by HC>
            if (standAloneAP) {
                dbgPrintln(EMMDBG_WIFI, "ESP-AP mode, connect only to Wifi AP");
                continue;
            }
            //</added by HC>

            if (! match_bssid(WiFi.BSSIDstr(i).c_str())) {
                dbgPrintln(EMMDBG_WIFI, "Failed to match BSSID");
                continue;
            } else {
                //<added by HC>
                knownNetworksFound += 1;
                //</added by HC>
            }
        }
        dbgPrintln(EMMDBG_WIFI, "RSSI: " + String(WiFi.RSSI(i)));
        int rssi = WiFi.RSSI(i);
        //sort by RSSI
        for(int j = 0; j < LAST_AP; j++) {
            if(ap[j].ssid_idx == NETWORK_LAST_INDEX ||
               (network_idx >= 0 &&
                  (ap[j].ssid_idx == NETWORK_MESH_NODE || rssi > ap[j].rssi)) ||
               (network_idx == NETWORK_MESH_NODE && ap[j].ssid_idx == NETWORK_MESH_NODE && rssi > ap[j].rssi))
            {
                for(int k = LAST_AP -1; k > j; k--) {
                    ap[k] = ap[k-1];
                }
                ap[j].rssi = rssi;
                ap[j].ssid_idx = network_idx;
                strlcpy(ap[j].bssid, WiFi.BSSIDstr(i).c_str(), sizeof(ap[j].bssid));
                break;
            }
        }
    }
    //<added by HC>
    dbgPrintln(EMMDBG_WIFI, "knownNetworksFound: " + String(knownNetworksFound));
    if (knownNetworksFound > 0) {
        standAloneAP = false;
        dbgPrintln(EMMDBG_WIFI, "standAloneAP: " + String(standAloneAP));
    }

    if (knownNetworksFound == 0 && wifiDisconnectedTime + random(120000, 240000) < millis()) {
        standAloneAP = true;
        dbgPrintln(EMMDBG_WIFI, "standAloneAP: " + String(standAloneAP));
    }
    //</added by HC>
}

void ESP8266MQTTMesh::schedule_connect(float delay) {
    dbgPrintln(EMMDBG_WIFI, "Scheduling reconnect for " + String(delay,2)+ " seconds from now");
    schedule.once(delay, connect, this);
}

void ESP8266MQTTMesh::connect() {
    if (WiFi.isConnected()) {
        dbgPrintln(EMMDBG_WIFI, "Called connect when already connected!");
        return;
    }
    connecting = false;
    lastReconnect = millis();
    //changed by HC:
    if (standAloneAP || scanning || ap_idx >= LAST_AP ||  ap[ap_idx].ssid_idx == NETWORK_LAST_INDEX) {
        scan();
        if (ap_idx >= LAST_AP) {
            // We got a disconnect during scan, we've been rescheduled already
            return;
        }
    } if (scanning) {
        schedule_connect(0.5);
        return;
    }

    //<added by HC>
    if (prevStandAloneAP != standAloneAP) {
        if (standAloneAP) {
            Serial.println("Setup AP..." );
            setup_AP();
        } else {
            Serial.println("Shutdown AP..." );
            shutdown_AP();
        }
    }
    prevStandAloneAP = standAloneAP;

    if (standAloneAP) {
        schedule_connect(60.0);
        return;
    }
    //</added by HC>
    if (ap[ap_idx].ssid_idx == NETWORK_LAST_INDEX) {
        // No networks found, try again
        schedule_connect();
        return;
    }
    for (int i = 0; i < LAST_AP; i++) {
        if (ap[i].ssid_idx == NETWORK_LAST_INDEX)
            break;
        dbgPrintln(EMMDBG_WIFI, String(i) + String(i == ap_idx ? " * " : "   ") + String(ap[i].bssid) + " " + String(ap[i].rssi));
    }
    char ssid[64];
    dbgPrintln(EMMDBG_WIFI, String("ap[ap_idx].ssid_idx: ") + String(ap[ap_idx].ssid_idx));
    if (ap[ap_idx].ssid_idx == NETWORK_MESH_NODE) {
        //This is a mesh node
        char subdomain_c[8];
        char filename[32];
        strlcpy(filename, "/bssid/", sizeof(filename));
        strlcat(filename, ap[ap_idx].bssid, sizeof(filename));
        int subdomain = read_subdomain(filename);
        if (subdomain == -1) {
            ap_idx++;
            schedule_connect();
            return;
        }
        itoa(subdomain, subdomain_c, 10);
        strlcpy(ssid, base_ssid, sizeof(ssid));
        strlcat(ssid, subdomain_c, sizeof(ssid));
        meshConnect = true;
    } else {
        strlcpy(ssid, networks[ap[ap_idx].ssid_idx], sizeof(ssid));
        //<changed by HC>
        if (strcmp(networks[ap[ap_idx].ssid_idx], "ESP-AP") == 0) {
          meshConnect = true;
        } else {
          meshConnect = false;
        }
        //</changed by HC>
    }
    dbgPrintln(EMMDBG_WIFI, "Connecting to SSID : '" + String(ssid) + "' BSSID '" + String(ap[ap_idx].bssid) + "'");
    const char *password = meshConnect ? mesh_password : network_password;
    //WiFi.begin(ssid.c_str(), password.c_str(), 0, WiFi.BSSID(best_match), true);
    WiFi.begin(ssid, password);
    connecting = true;
    lastStatus = lastReconnect;
}

void ESP8266MQTTMesh::parse_message(const char *topic, const char *msg) {
  int inTopicLen = strlen(inTopic);

  dbgPrintln(EMMDBG_MQTT, "Parse " + String(topic) + " " + String(msg));

  if (strstr(topic, inTopic) != topic) {
      return;
  }
  const char *subtopic = topic + inTopicLen;
  if (strstr(subtopic,"bssid/") == subtopic) {
      const char *bssid = subtopic + 6;
      char filename[32];
      strlcpy(filename, "/bssid/", sizeof(filename));
      strlcat(filename, bssid, sizeof(filename));
      int idx = strtoul(msg, NULL, 10);
      int subdomain = read_subdomain(filename);
      if (subdomain == idx) {
          // The new value matches the stored value
          return;
      }
      File f = SPIFFS.open(filename, "w");
      if (! f) {
          dbgPrintln(EMMDBG_MQTT, "Failed to write /" + String(bssid));
          return;
      }
      f.print(msg);
      f.print("\n");
      f.close();

      if (strcmp(WiFi.softAPmacAddress().c_str(), bssid) == 0) {
          shutdown_AP();
          setup_AP();
      }
      return;
  }
  if (! callback) {
      return;
  }

  callback(topic, msg);

  if(strstr(subtopic, "broadcast/") == subtopic) {
      //Or messages sent to all nodes
      callback(subtopic + 10, msg);
  }
}

void ESP8266MQTTMesh::schedule_connect_mqtt(float delay) {
    dbgPrintln(EMMDBG_WIFI, "Scheduling connect_mqtt for " + String(delay, 2)+ " seconds from now");
    schedule.once(delay, connect_mqtt, this);
}

void ESP8266MQTTMesh::connect_mqtt() {

    // Attempt to connect
    if (!mqttClient.connected() && settings.mqttServer().length() > 0) {
      dbgPrintln(EMMDBG_MQTT, "Attempting MQTT connection (" + settings.mqttServer() + ":" + String(settings.mqttPort()) + ")...");
      mqttClient.connect();
      schedule_connect_mqtt(1.0);
    }
}


void ESP8266MQTTMesh::publish(const char *subtopic, const char *msg, const bool retain) {
    char topic[TOPIC_LEN];
    //strlcpy(topic, outTopic, sizeof(topic)); //HC: outtopic is added earlier already
    //strlcat(topic, mySSID, sizeof(topic));
    strlcpy(topic, subtopic, sizeof(topic));
    dbgPrintln(EMMDBG_MQTT_EXTRA, "Sending: " + String(topic) + "=" + String(msg));
    //<added by HC>
    if ((standAloneAP || mqttDisConnect) && !meshConnect) {
      dbgPrintln(EMMDBG_MQTT, "standAloneAP || mqttDisConnect");
	     if (strstr(topic, inTopic)) {
        dbgPrintln(EMMDBG_MQTT, "Send  inTopic message to clients espClient[1-4]...");
        for (int i = 1; i <= ESP8266_NUM_CLIENTS; i++) {
          if (espClient[i]) {
            send_message(i, topic, msg);
          }
        }
      }
    } else if (meshConnect) {
        dbgPrintln(EMMDBG_MQTT, "Send message to upper espClient[0]...");
        send_message(0, topic, msg);
    } else {
        dbgPrintln(EMMDBG_MQTT, "Send message to MQTT server...");
        mqttClient.publish(topic, 0, retain, msg);
    }
    //</added by HC>
}

void ESP8266MQTTMesh::shutdown_AP() {
    if(!AP_ready)
        return;
    //<Disabled by HC: this is also done already by OnDisconnected function, doing twice causes crash>
    //for (int i = 1; i <= ESP8266_NUM_CLIENTS; i++) {
        // if(espClient[i]) {
        //     dbgPrintln(EMMDBG_MSG_EXTRA, "Deleting espClient[i]: " + String(i));
        //     espClient[i]->close(true);
        //     delete espClient[i];
        //     espClient[i] = NULL;
        // }
    //}
    //</Disabled by HC>
    dbgPrintln(EMMDBG_MSG_EXTRA, "AP disconnecting...");
    AP_ready = false;
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
    dbgPrintln(EMMDBG_MSG_EXTRA, "AP disconnecting done");
}

void ESP8266MQTTMesh::setup_AP() {
    if (AP_ready)
        return;
    char filename[32];
    strlcpy(filename, "/bssid/", sizeof(filename));
    strlcat(filename, WiFi.softAPmacAddress().c_str(), sizeof(filename));
    int subdomain = read_subdomain(filename);
    if (subdomain == -1) {
        return;
    }
    char subdomainStr[4];
    itoa(subdomain, subdomainStr, 10);
    strlcpy(mySSID, base_ssid, sizeof(mySSID));
    strlcat(mySSID, subdomainStr, sizeof(mySSID));
    IPAddress apIP(192, 168, subdomain, 1);
    IPAddress apGateway(192, 168, subdomain, 1);
    IPAddress apSubmask(255, 255, 255, 0);
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(apIP, apGateway, apSubmask);

    //<added by HC>
    if (standAloneAP) {
        WiFi.softAP("ESP-AP", mesh_password, WiFi.channel(), 0);
        dbgPrintln(EMMDBG_WIFI, "Initialized AP as 'ESP-AP " + apIP.toString() + "'");
    } else {
        WiFi.softAP(mySSID, network_password, WiFi.channel(), 1);
        dbgPrintln(EMMDBG_WIFI, "Initialized AP as '" + String(mySSID) + "'  IP '" + apIP.toString() + "'");
    }
    //</added by HC>

    strlcat(mySSID, "/", sizeof(mySSID));
    if (meshConnect) {
        //<changed by HC>
        publish("mesh_cmd", "request_bssid", false);
        //</changed by HC>
    }
    connecting = false; //Connection complete
    AP_ready = true;
}
int ESP8266MQTTMesh::read_subdomain(const char *fileName) {
      char subdomain[4];
      File f = SPIFFS.open(fileName, "r");
      if (! f) {
          dbgPrintln(EMMDBG_MSG_EXTRA, "Failed to read " + String(fileName));
          return -1;
      }
      subdomain[f.readBytesUntil('\n', subdomain, sizeof(subdomain)-1)] = 0;
      f.close();
      unsigned int value = strtoul(subdomain, NULL, 10);
      if (value < 0 || value > 255) {
          dbgPrintln(EMMDBG_MSG, "Illegal value '" + String(subdomain) + "' from " + String(fileName));
          return -1;
      }
      return value;
}
void ESP8266MQTTMesh::assign_subdomain() {
    char seen[256];
    if (match_bssid(WiFi.softAPmacAddress().c_str())) {
        return;
    }
    memset(seen, 0, sizeof(seen));
    Dir dir = SPIFFS.openDir("/bssid/");
    while(dir.next()) {
      int value = read_subdomain(dir.fileName().c_str());
      if (value == -1) {
          continue;
      }
      dbgPrintln(EMMDBG_WIFI_EXTRA, "Mapping " + dir.fileName() + " to " + String(value) + " ");
      seen[value] = 1;
    }
    for (int i = 4; i < 256; i++) {
        if (! seen[i]) {
            File f = SPIFFS.open("/bssid/" +  WiFi.softAPmacAddress(), "w");
            if (! f) {
                dbgPrintln(EMMDBG_MSG, "Couldn't write "  + WiFi.softAPmacAddress());
                die();
            }
            f.print(i);
            f.print("\n");
            f.close();
            //Yes this is meant to be inTopic.  That allows all other nodes to see this message
            char topic[TOPIC_LEN];
            char msg[4];
            itoa(i, msg, 10);
            strlcpy(topic, inTopic, sizeof(topic));
            strlcat(topic, "bssid/", sizeof(topic));
            strlcat(topic, WiFi.softAPmacAddress().c_str(), sizeof(topic));
            dbgPrintln(EMMDBG_MQTT_EXTRA, "Publishing " + String(topic) + " == " + String(i));
            mqttClient.publish(topic, 0, true, msg);
            setup_AP();
            return;
        }
    }
}

//<Added by HC>
void ESP8266MQTTMesh::schedule_check_ack(float delay) {
    //dbgPrintln(EMMDBG_WIFI, "Scheduling ack check for " + String(delay, 2) + " millis from now");
    checkAckTicker.once(delay, check_ack, this);
}

void ESP8266MQTTMesh::check_ack() {
  for (uint8_t idx = 0; idx <= 4; idx++) {
    if (ackTimer[idx] != 0 && millis() - ackTimer[idx] > 10000) {
      if (idx == 0 && meshConnect && !standAloneAP) {
        dbgPrintln(EMMDBG_MQTT, "Ack timeout to mesh, WiFi.disconnect()");
        WiFi.disconnect();
        meshConnect = false;
        schedule_connect();
      } else {
        if (espClient[idx]) {
          dbgPrintln(EMMDBG_MQTT, "Ack timeout, closing espclient: " + String(idx));
          espClient[idx]->free();
          espClient[idx]->close(true);
        }
      }
      ackTimer[idx] = 0;
    }
  }
  schedule_check_ack(10.0);
  dbgPrintln(EMMDBG_MQTT, "ESP.getFreeHeap(): " + String(ESP.getFreeHeap()));
}
//</Added by HC>

bool ESP8266MQTTMesh::send_message(int index, const char *topicOrMsg, const char *msg) {

  dbgPrintln(EMMDBG_MQTT, "index: " + String(index));
  dbgPrintln(EMMDBG_MQTT, "topicOrMsg: " + String(topicOrMsg));
  dbgPrintln(EMMDBG_MQTT, "msg: " + String(msg));

  espClient[index]->write(topicOrMsg);
  if (msg) {
      espClient[index]->write("=", 1);
      espClient[index]->write(msg);
  }
  espClient[index]->write("\0", 1);

  ackTimer[index] = millis();
  return true;
}

void ESP8266MQTTMesh::broadcast_message(const char *topicOrMsg, const char *msg) {
    for (int i = 1; i <= ESP8266_NUM_CLIENTS; i++) {
        if (espClient[i]) {
            send_message(i, topicOrMsg, msg);
        }
    }
}

void ESP8266MQTTMesh::send_bssids(int idx) {
    Dir dir = SPIFFS.openDir("/bssid/");
    char msg[128];
    char subdomainStr[4];
    while(dir.next()) {
        //<added by HC>
        wdt_reset();
        //<added by HC>
        int subdomain = read_subdomain(dir.fileName().c_str());
        if (subdomain == -1) {
            continue;
        }
        itoa(subdomain, subdomainStr, 10);
        strlcpy(msg, inTopic, sizeof(msg));
        strlcat(msg, "bssid/", sizeof(msg));
        strlcat(msg, dir.fileName().substring(7).c_str(), sizeof(msg)); // bssid
        strlcat(msg, "=", sizeof(msg));
        strlcat(msg, subdomainStr, sizeof(msg));
        send_message(idx, msg);
    }
}


void ESP8266MQTTMesh::handle_client_data(int idx, char *data) {
            //<added by HC>
            wdt_reset();
            //<added by HC>
            dbgPrintln(EMMDBG_MQTT, "Received: msg from " + espClient[idx]->remoteIP().toString() + " on " + (idx == 0 ? "STA" : "AP"));
            dbgPrintln(EMMDBG_MQTT_EXTRA, "--> '" + String(data) + "'");
            char topic[64];
            const char *msg;
            if (! keyValue(data, '=', topic, sizeof(topic), &msg)) {
                dbgPrintln(EMMDBG_MQTT, "Failed to handle message");
                return;
            }
            if (idx == 0 || standAloneAP || mqttDisConnect) {
                //This is a packet from MQTT or to inTopic from Mesh, need to rebroadcast to each connected station
                if (strstr(topic, inTopic)) {
                  if (!strstr(topic, "bssid/")) {
                    dbgPrintln(EMMDBG_MQTT, "Broadcast incoming message...");
                    broadcast_message(data);
                  }
                }
                parse_message(topic, msg);
            } else {
                if (strstr(topic, "mesh_cmd")) {
                    // We will handle this packet locally
                    if (strstr(msg, "request_bssid")) {
                        send_bssids(idx);
                    }
                } else {
                    if (!meshConnect) {
                        dbgPrintln(EMMDBG_MQTT, "Send message to MQTT server...");
                        mqttClient.publish(topic, 0, false, msg);
                    } else {
                        dbgPrintln(EMMDBG_MQTT, "Send message to root AP...");
                        send_message(0, data);
                    }
                }
            }
}

bool ESP8266MQTTMesh::keyValue(const char *data, char separator, char *key, int keylen, const char **value) {
  int maxIndex = strlen(data)-1;
  int i;
  for(i=0; i<=maxIndex && i <keylen-1; i++) {
      key[i] = data[i];
      if (key[i] == separator) {
          *value = data+i+1;
          key[i] = 0;
          return true;
      }
  }
  key[i] = 0;
  *value = NULL;
  return false;
}

void ESP8266MQTTMesh::onWifiConnect(const WiFiEventStationModeGotIP& event) {
    if (meshConnect) {
        dbgPrintln(EMMDBG_WIFI, "Connecting to mesh: " + WiFi.gatewayIP().toString() + " on port: " + String(mesh_port));
#if ASYNC_TCP_SSL_ENABLED
        espClient[0]->connect(WiFi.gatewayIP(), mesh_port, mesh_secure);
#else
        espClient[0]->connect(WiFi.gatewayIP(), mesh_port);
#endif
        bufptr[0] = inbuffer[0];
    } else {
        dbgPrintln(EMMDBG_WIFI, "Connecting to mqtt");
        connect_mqtt();
    }
}

void ESP8266MQTTMesh::onWifiDisconnect(const WiFiEventStationModeDisconnected& event) {

    //<added by HC>
    wifiDisconnectedTime = millis();
    //</added by HC>

    //Reasons are here: ESP8266WiFiType.h-> WiFiDisconnectReason
    dbgPrintln(EMMDBG_WIFI, "Disconnected from Wi-Fi: " + event.ssid + " because: " + String(event.reason));
    WiFi.disconnect();
    if (! connecting) {
        ap_idx = LAST_AP;
    } else if (event.reason == WIFI_DISCONNECT_REASON_ASSOC_TOOMANY  && retry_connect) {
        // If we rebooted without a clean shutdown, we may still be associated with this AP, in which case
        // we'll be booted and should try again
        retry_connect--;
    } else {
        ap_idx++;
    }
    schedule_connect();
}

//void ESP8266MQTTMesh::onDHCPTimeout() {
//    dbgPrintln(EMMDBG_WIFI, "Failed to get DHCP info");
//}

void ESP8266MQTTMesh::onAPConnect(const WiFiEventSoftAPModeStationConnected& ip) {
    dbgPrintln(EMMDBG_WIFI, "Got connection from Station");
}

void ESP8266MQTTMesh::onAPDisconnect(const WiFiEventSoftAPModeStationDisconnected& ip) {
    dbgPrintln(EMMDBG_WIFI, "Got disconnection from Station");
}

void ESP8266MQTTMesh::onMqttConnect(bool sessionPresent) {
    dbgPrintln(EMMDBG_MQTT, "MQTT Connected");
    // Once connected, publish an announcement...
    char id[9];
	char topic[128];
    char msg[64];

	itoa(firmware_id, id, 16);
    snprintf(topic, sizeof(topic), "%sstate/%s/connect", outTopic, WiFi.macAddress().c_str());
    snprintf(msg, sizeof(msg), "Connected node : %s", WiFi.localIP().toString().c_str());

    mqttClient.publish(topic, 0, true, msg);
    // ... and resubscribe
    char subscribe[TOPIC_LEN];
    strlcpy(subscribe, inTopic, sizeof(subscribe));
    strlcat(subscribe, "#", sizeof(subscribe));
    mqttClient.subscribe(subscribe, 0);

    if (match_bssid(WiFi.softAPmacAddress().c_str())) {
        setup_AP();
    } else {
        //If we don't get a mapping for our BSSID within 10 seconds, define one
        schedule.once(10.0, assign_subdomain, this);
    }
    //<added byHC>
    mqttDisConnect = false;
    //</added byHC>
}

void ESP8266MQTTMesh::onMqttDisconnect(AsyncMqttClientDisconnectReason reason) {
    int r = (int8_t)reason;
    dbgPrintln(EMMDBG_MQTT, "Disconnected from MQTT: " + String(r));
#if ASYNC_TCP_SSL_ENABLED
    if (reason == AsyncMqttClientDisconnectReason::TLS_BAD_FINGERPRINT) {
        dbgPrintln(EMMDBG_MQTT, "Bad MQTT server fingerprint.");
        if (WiFi.isConnected()) {
            WiFi.disconnect();
            schedule_connect();
        }
        return;
    }
#endif
    //shutdown_AP();
    if (WiFi.isConnected()) {

        //<added byHC>
        if (!mqttDisConnect) {
            connect_mqtt();
            mqttDisConnect = true;
            mqttDisconnectedTime = millis();
        }
        //</added byHC>
    }
}

void ESP8266MQTTMesh::onMqttSubscribe(uint16_t packetId, uint8_t qos) {
  Serial.println("Subscribe acknowledged.");
  Serial.print("  packetId: ");
  Serial.println(packetId);
  Serial.print("  qos: ");
  Serial.println(qos);
}

void ESP8266MQTTMesh::onMqttUnsubscribe(uint16_t packetId) {
  Serial.println("Unsubscribe acknowledged.");
  Serial.print("  packetId: ");
  Serial.println(packetId);
}

void ESP8266MQTTMesh::onMqttMessage(char* topic, char* payload, AsyncMqttClientMessageProperties properties, size_t len, size_t index, size_t total) {
  //<added by HC>
  wdt_reset();
  //<added by HC>
  memcpy(inbuffer[0], payload, len);
  inbuffer[0][len]= '\0';
  dbgPrintln(EMMDBG_MQTT_EXTRA, "Message arrived [" + String(topic) + "] '" + String(inbuffer[0]) + "'");
  broadcast_message(topic, inbuffer[0]);
  parse_message(topic, inbuffer[0]);
}

void ESP8266MQTTMesh::onMqttPublish(uint16_t packetId) {
  //Serial.println("Publish acknowledged.");
  //Serial.print("  packetId: ");
  //Serial.println(packetId);
}

#if ASYNC_TCP_SSL_ENABLED
int ESP8266MQTTMesh::onSslFileRequest(const char *filename, uint8_t **buf) {
    File file = SPIFFS.open(filename, "r");
    if(file){
      size_t size = file.size();
      uint8_t * nbuf = (uint8_t*)malloc(size);
      if(nbuf){
        size = file.read(nbuf, size);
        file.close();
        *buf = nbuf;
        dbgPrintln(EMMDBG_WIFI, "SSL File: " + filename + " Size: " + String(size));
        return size;
      }
      file.close();
    }
    *buf = 0;
    dbgPrintln(EMMDBG_WIFI, "Error reading SSL File: " + filename);
    return 0;
}
#endif
void ESP8266MQTTMesh::onClient(AsyncClient* c) {
    dbgPrintln(EMMDBG_WIFI, "Got client connection from: " + c->remoteIP().toString());

    for (int i = 1; i <= ESP8266_NUM_CLIENTS; i++) {
        if (!espClient[i]) {
            espClient[i] = c;

            //<changed bt HC>espClient[i]->setNoDelay(false);

            espClient[i]->onDisconnect([this](void * arg, AsyncClient *c)                           { this->onDisconnect(c);      }, this);
            espClient[i]->onError(     [this](void * arg, AsyncClient *c, int8_t error)             { this->onError(c, error);    }, this);
            espClient[i]->onAck(       [this](void * arg, AsyncClient *c, size_t len, uint32_t time){ this->onAck(c, len, time);  }, this);
            espClient[i]->onTimeout(   [this](void * arg, AsyncClient *c, uint32_t time)            { this->onTimeout(c, time);   }, this);
            espClient[i]->onData(      [this](void * arg, AsyncClient *c, void* data, size_t len)   { this->onData(c, data, len); }, this);
            bufptr[i] = inbuffer[i];
            return;
        }
    }
    dbgPrintln(EMMDBG_WIFI, "Discarding client connection from: " + c->remoteIP().toString());
    delete c;
}

void ESP8266MQTTMesh::onConnect(AsyncClient* c) {
    dbgPrintln(EMMDBG_WIFI, "Connected to mesh");
#if ASYNC_TCP_SSL_ENABLED
    if (mesh_secure) {
        SSL* clientSsl = c->getSSL();
        bool sslFoundFingerprint = false;
        uint8_t *fingerprint;
        if (! clientSsl) {
            dbgPrintln(EMMDBG_WIFI, "Connection is not secure");
        } else if(onSslFileRequest("/ssl/fingerprint", &fingerprint)) {
            if (ssl_match_fingerprint(clientSsl, fingerprint) == SSL_OK) {
                sslFoundFingerprint = true;
            }
            free(fingerprint);
        }

        if (!sslFoundFingerprint) {
            dbgPrintln(EMMDBG_WIFI, "Couldn't match SSL fingerprint");
            c->free();
            c->close(true);
            return;
        }
    }
#endif

    if (match_bssid(WiFi.softAPmacAddress().c_str())) {
        setup_AP();
    }
}

void ESP8266MQTTMesh::onDisconnect(AsyncClient* c) {
    if (c == espClient[0]) {

		//<added by HC>
        wifiDisconnectedTime = millis();
        //</added by HC>

        dbgPrintln(EMMDBG_WIFI, "Disconnected from mesh");
        shutdown_AP();
        WiFi.disconnect();
        schedule_connect();
        return;
    }
    for (int i = 1; i <= ESP8266_NUM_CLIENTS; i++) {
        if (c == espClient[i]) {
            dbgPrintln(EMMDBG_WIFI, "Disconnected from AP");

            //<Modified by HC to avoid crashing>
            if (espClient[i]) {
        	    dbgPrintln(EMMDBG_MSG_EXTRA, "Deleting espClient[i]: " + String(i));
              espClient[i]->free();
              delete c;
              espClient[i] = NULL;
              dbgPrintln(EMMDBG_MSG_EXTRA, "Deleting espClient[i] done");
            }
            //</Modified by HC>
        }
    }
    dbgPrintln(EMMDBG_WIFI, "Disconnected unknown client");
}
void ESP8266MQTTMesh::onPoll(AsyncClient* c) {
    //dbgPrintln(EMMDBG_WIFI, "Got poll on " + c->remoteIP().toString());
}
void ESP8266MQTTMesh::onError(AsyncClient* c, int8_t error) {
    dbgPrintln(EMMDBG_WIFI, "Got error on " + c->remoteIP().toString() + ": " + String(error));
}
void ESP8266MQTTMesh::onAck(AsyncClient* c, size_t len, uint32_t time) {
    dbgPrintln(EMMDBG_WIFI_EXTRA, "Got ack on " + c->remoteIP().toString() + ": " + String(len) + " / " + String(time));
    for (int idx = 0; idx <= ESP8266_NUM_CLIENTS; idx++) {
        if (espClient[idx] == c) {
            dbgPrintln(EMMDBG_WIFI_EXTRA, "Reset ack timer on espClient " + String(idx));
            ackTimer[idx] = 0;
            return;
        }
    }
}

void ESP8266MQTTMesh::onTimeout(AsyncClient* c, uint32_t time) {
    dbgPrintln(EMMDBG_WIFI, "Got timeout  " + c->remoteIP().toString() + ": " + String(time));
    c->close();
}

void ESP8266MQTTMesh::onData(AsyncClient* c, void* data, size_t len) {
    dbgPrintln(EMMDBG_WIFI_EXTRA, "Got data from " + c->remoteIP().toString());
    for (int idx = meshConnect ? 0 : 1; idx <= ESP8266_NUM_CLIENTS; idx++) {

        if (espClient[idx] == c) {
            char *dptr = (char *)data;
            for (int i = 0; i < len; i++) {
                *bufptr[idx]++ = dptr[i];
                if(! dptr[i]) {
                    handle_client_data(idx, inbuffer[idx]);
                    bufptr[idx] = inbuffer[idx];
                }
            }
            return;
        }
    }
    dbgPrintln(EMMDBG_WIFI, "Could not find client");
}
