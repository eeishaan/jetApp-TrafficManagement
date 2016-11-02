#!/usr/bin/env python

import collections
import datetime
import glob
import json
import logging
import os
import re
import smtplib
import struct
import sys
import time

import grpc
import paho.mqtt.client as mqtt

import authentication_service_pb2
import jnx_addr_pb2
import prpd_common_pb2
import rib_service_pb2 as Route

sender = 'JET-Router-R1@juniper.net'
receivers = ['ishaank@juniper.net']

R1 = 'abcd'
R1_IFL_SNMP_INDEX = '511'
DIP = '1.1.1.1/32'
NIP = '10.1.1.2'
APP_USER = 'abcd'
APP_PASSWORD = 'abcd'

DEFAULT_ROUTE_NEXTHOP_IP = NIP
DEFAULT_ROUTE_GET_TABLE_NAME = 'inet.0'
DEFAULT_ROUTE_GET_PREFIX = '1.1.1.1'

DEFAULT_TOPIC = "#"                           # Implies all value
SYSLOG_TOPIC_HEADER = r"/junos/events/syslog"  # Syslog event topic header
DEFAULT_MQTT_PORT = 1883            # Default JET notification port
DEFAULT_MQTT_IP = '127.0.0.1'       # Default JET address for MQTT
DEFAULT_MQTT_TIMEOUT = 60           # Default Notification channel timeout

logger = logging.getLogger(__name__)
handlers = collections.defaultdict(set)
route_stub = None


def _authenticateChannel(channel, user, passw, client_id):
    sec_stub = authentication_service_pb2.LoginStub(channel)
    cred = authentication_service_pb2.LoginRequest(user_name=user,
                                                   password=passw,
                                                   client_id=client_id)
    res = sec_stub.LoginCheck(cred)
    return res


def _createSyslogTopic(event_id=DEFAULT_TOPIC):
        """
        This method creates the syslog topic.
        :param event_id: Syslog event id. Default is all syslog events.
        :return: Returns the Topic Object
        """
        data = {}
        data['event_id'] = event_id
        data['topic'] = "{0}/{1}".format(SYSLOG_TOPIC_HEADER, data['event_id'])
        data['subscribed'] = 0
        logger.info('Successfully appended the topic %s' % data['topic'])
        return type('Topic', (), data)


def _subscribe(mqtt_client, subscriptionType, handler=None, qos=0):
        """
        This method subscribes to a specific topic the client app is interested
        in. This takes subscription type and the callback function as parameters.
        When the notification for the subscribed topic is received, user passed
        callback function will be called. Callback function receives the
        notification message in json format.
        :param mqtt_client = mqtt client object to subsribe to
        :param subscriptionType : Type of notification user wants to subscribe
        :param handler: Callback function for each notification
        """
        global handlers
        topic = subscriptionType.topic
        mqtt_client.subscribe(topic, qos)
        subscriptionType.subscribed = 1
        if(handler):
            handlers[topic].add(handler)
        logger.info('Successfully subscribed to event:%s'
                    % subscriptionType.topic)


def _on_message_cb(client, obj, msg):
        """
        This method will invoke the specified callback handler by the client app
        when a notification is received by the app based on the notification type.
        :param client: the client instance for this callback
        :param obj: the private user data as set in Client() or userdata_set()
        :param msg: an instance of Message. This is a class with members topic, payload, qos, retain
        """
        payload = msg.payload
        topic = msg.topic
        json_data = None
        decoder = json.JSONDecoder()
        json_data, end = decoder.raw_decode(payload)
        if json_data is None:
            logger.error('Received event has invalid JSON format')
            logger.error('Received payload: %s' % payload)
        if len(payload) != end:
            logger.error('Received event has additional invalid JSON format')
            logger.error('It has the following additional content: %s'
                         % payload[end:])
        callback_called = False
        for cbs in handlers:
            if cbs != '#':
                if mqtt.topic_matches_sub(cbs, topic):
                    for cb in handlers.get(cbs, []):
                        cb(json_data)
                        callback_called = True

        if callback_called is False:
            for cb in handlers.get('#', []):
                logger.debug('Sending data to callback %s' % cb)
                cb(json_data)


def _openNotificationSession(device=DEFAULT_MQTT_IP, port=DEFAULT_MQTT_PORT,
                             user=None, password=None, tls=None,
                             keepalive=DEFAULT_MQTT_TIMEOUT,
                             bind_address="", is_stream=False):
        """
        Create a request response session with the  JET server. Raises
        exception in case of invalid arguments or when JET notification
        server is not accessible.
        :param device: JET Server IP address. Default is localhost
        :param port: JET Notification port number. Default is 1883
        :param user: Username on the JET server, used for authentication and authorization.
        :param password: Password to access the JET server, used for authentication and authorization.
        :param keepalive: Maximum period in seconds between communications with the broker. Default is 60.
        :param bind_address: Client source address to bind. Can be used to control access at broker side.
        :return: JET Notification object.
        """
        try:
            notifier_client = mqtt.Client()
            logger.info('Connecting to JET notification server')
            notifier_client.connect(device, port, keepalive, bind_address)
            notifier_client.loop_start()
            notifier_client.on_message = _on_message_cb
        except struct.error as err:
            message = err.message
            err.message = 'Invalid argument value passed in %s at line no. %s\n\
                           Error: %s' % (traceback.extract_stack()[0][0],
                                         traceback.extract_stack()[0][1],
                                         message)
            logger.error('%s' % (err.message))
            raise err
        except Exception, tx:
            tx.message = 'Could not connect to the JET notification server'
            logger.error('%s' % (tx.message))
            raise Exception(tx.message)

        return notifier_client


def _get_route_match_fields(addr, table_name, prefix_len):
    """
    Constructs a Route.RouteMatchFields out of the given arguments
    :param addr:IPv4 address of the route
    :param table_name: Table that route belongs to
    :param prefix_len: Prefix len of route
    """
    netaddr = _get_network_addr(addr)
    rttablename = prpd_common_pb2.RouteTableName(name=table_name)
    routeTable = prpd_common_pb2.RouteTable(rtt_name=rttablename)
    return Route.RouteMatchFields(dest_prefix=netaddr,
                                  dest_prefix_len=prefix_len,
                                  table=routeTable)


def _get_network_addr(addr_string):
    """
    Constructs a prpd_common_pb2.NetworkAddress object from the string
    :param addr_string: IPv4 string
    :return: return prpd_common_pb2.NetworkAddress 
    """
    ip = jnx_addr_pb2.IpAddress(addr_string=addr_string)
    return prpd_common_pb2.NetworkAddress(inet=ip)


def on_message(message):
    print("----------------------------------------EVENT RECEIVED-------------------------------------------")
    print "Event Type : " + message['jet-event']['event-id']

    if 'attributes' in message['jet-event'].keys():
        print "Event Attributes : ", message['jet-event']['attributes']['message']
    else:
        print "Attributes : NULL"
    print("-------------------------------------------------------------------------------------------------")

    p1 = re.search(r"Event " + re.escape(R1_IFL_SNMP_INDEX) + r" triggered by Alarm 1, (\w+) threshold",
                   str(message['jet-event']['attributes']))
    res = p1.group(1)
    route_present = None
    if (res == "rising") and (route_present is not True):
        print ("\n>>>>>>>>>>>>>>Primary Path input traffic rate is above threshold value<<<<<<<<<<<<<<<<<<<")
        routematchFields = _get_route_match_fields(DEFAULT_ROUTE_GET_PREFIX,
                                                   DEFAULT_ROUTE_GET_TABLE_NAME,
                                                   32)
        routeAddr = _get_network_addr(DEFAULT_ROUTE_NEXTHOP_IP)
        gateway_list = [Route.RouteGateway(gateway_address=routeAddr)]
        nexthop_list = Route.RouteNexthop(gateways=gateway_list)

        route_entry = [Route.RouteEntry(key=routematchFields,
                                        nexthop=nexthop_list)]
        route_request = Route.RouteUpdateRequest(routes=route_entry)
        result = route_stub.RouteAdd(route_request)

        if result.status is Route.SUCCESS:
            route_present = True
            print "Added static route directly into control plane"
            print "Traffic to destination subnets routed via Secondary path"
            print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            print '\n#############################Verifying RIB#######################################'
            routematchFields = _get_route_match_fields(DEFAULT_ROUTE_GET_PREFIX,
                                                       DEFAULT_ROUTE_GET_TABLE_NAME,
                                                       0)
            rrequest = Route.RouteGetRequest(key=routematchFields)
            result = route_stub.RouteGet(rrequest)
            for single_res in result:
                for route in single_res.routes:
                    hops = route.nexthop
                    for nexthop_ip in hops.gateways:
                        print 'Next Hop Ips are:', nexthop_ip.gateway_address.inet.addr_string
                        if nexthop_ip.gateway_address.inet.addr_string == NIP:
                            print "Route add API injected route successfully"
            print '##################################################################################'
            mail(message="""Subject: JET Notification:Traffic rate is above threshold on primary path. 
                             Body: JET App rerouted traffic via secondary path""")
        else:
            print "V4RouteAdd service API activation failed \n"
            route_present = False
    elif (res == "falling") and (route_present is not False):
        print ("\n>>>>>>>>>>>>>>Primary Path input traffic rate is below threshold value<<<<<<<<<<<<<<<<<<<")

        routematchFields = _get_route_match_fields(DEFAULT_ROUTE_GET_PREFIX,
                                                   DEFAULT_ROUTE_GET_TABLE_NAME,
                                                   32)
        route_fields = [routematchFields]
        route_rem_req = Route.RouteRemoveRequest(keys=route_fields)
        result = route_stub.RouteRemove(route_rem_req)
        if result.status is Route.SUCCESS:
            route_present = False
            print "Primary path input traffic rate is below threshold, since deleted route"
            print "Entire Traffic routed back via Primary path"
            print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            mail(message="""Subject: SMTP e-mail test JET App deleted route in R1""")
        else:
            print "V4RouteDelete service API deactivation failed \n"
            route_present = True
    else:
        print "No changes required \n"


def mail(message):
    smtpObj = smtplib.SMTP('smtp.juniper.net')
    smtpObj.sendmail(sender, receivers, message)
    print "Successfully sent email"


def main():
    global route_stub
    channel = grpc.insecure_channel(R1+':32767')
    res = _authenticateChannel(channel, APP_USER, APP_PASSWORD, '1212914')
    print "Authentication "+('success' if res else 'failure')
    if res is False:
        return
    route_stub = Route.RibStub(channel)
    try:
        # Create a mqtt_client
        mqtt_client = _openNotificationSession(device=R1)
        # Subscribe for relevant syslog events
        syslog = _createSyslogTopic("SNMPD_RMON_EVENTLOG")
        print "Subscribing to Syslog RMON notifications"
        _subscribe(mqtt_client, syslog, on_message)
        while 1:
            1 + 1
    except Exception as tx:
        print '%s' % tx.message

if __name__ == "__main__":
    main()
