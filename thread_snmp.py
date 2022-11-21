from pysnmp.hlapi import *
from pysnmp.proto import rfc1902
from time import sleep
import ipaddress, csv,threading
import socket




class snmp_rover_get_data :
 
     
     def __init__(self,target,oid,tarjeta, slot):
         ##iniciializo
         self.target = target
         self.comunity_read="public"
         self.port = 161
         self.tarjeta = tarjeta
         self.slot = slot
         
         self.splunk_ip="172.8.1.20"
         self.splunk_port=9001
         
         self.oid = oid ## ["1.3.6.1.4.1.19324.2.2.1.3.1.1.3.0"]

         self.info = {
                        "agent_rover_ip": self.target,
                        "agent_rover_tarjeta": self.tarjeta, # tipo de tarjeta dtmb satatelite ip
                        "agent_rover_slot":  self.slot, # posiciones de la tarjeta
                        "agent_rover_value_1": "0", #value1 puede ser rf level
                        "agent_rover_value_2": "0", #value1 puede ser rf  2 level
                        "agent_rover_value_3": "0" #value1 puede ser snrf level
                      }
         

     

     ##get snmp
     def get( self ):
       
          object_types = []
          for object_list in self.oid:
                    object_types.append( ObjectType( ObjectIdentity( object_list )))
              ## hace la peticion
          engine = SnmpEngine() ### snmp sock
          sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) ##udp sock        
          while True:  
                     
              handler   =  getCmd(
                                        engine,
                                        CommunityData(self.comunity_read, mpModel=0),
                                        UdpTransportTarget(( self.target , self.port ),timeout=2.0,retries=0),
                                        ContextData(),
                                        *object_types
                                      )

              
              ########################################################## espera respuesta analisis
            
              print (self.target  )
              sleep(3)
              ###################################################################################
              result = []
              for i in range( 1 ):
                    try:
                          error_indication, error_status, error_index, var_binds = next(handler)
                          if not error_indication and not error_status:
                                items = {}
                                #print ("result ok")
                                for var_bind in var_binds:
                                    #print( var_bind )
                                  
                                    try:
                                         items[str(var_bind[0])] =  int( var_bind[1] )
                                    except (ValueError, TypeError):
                                         try:
                                                items[str(var_bind[0])] = float( var_bind[1] )
                                         except (ValueError, TypeError):
                                               try:
                                                     address= rfc1902.IpAddress.prettyPrint( var_bind[1] )
                                                     if ipaddress.ip_address(address)  :
                                                            items[str(var_bind[0])] = str(address)
                                               except (ValueError, TypeError):
                                                     try:
                                                           items[str(var_bind[0])] = str( var_bind[1] )
                                                     except (ValueError, TypeError):
                                                           pass
                                        
                                result.append(items)
                          else:
                                result = str( error_status)
                                #print ( "error " + result) ### valor 0 si no hay respuesta
                    except StopIteration:
                          break
              #print ("" )
              ###result el valor de la respuesta
              if result == "noSuchName" or  result == "0":
                  print ( self.target + "  bye")
                  return
              #print ( result )
              ###send udp packet
              self.info [ "agent_rover_value_1" ] =  result[0][ self.oid[0] ]
              if len( result[0] ) == 2: 
                 self.info [ "agent_rover_value_2" ] =  result[0][ self.oid[1] ]
              if len( result[0] ) == 3: 
                 self.info [ "agent_rover_value_3" ] =  result[0][ self.oid[2] ]
              
            
              
              
              data = "{"
      
              for key in  self.info  : 
                     data = data +  "\""  + key  + "\":\"" + str(self.info  [ key ] ) + "\","
              data += " }\r\n"
            
               
              sock.sendto(data.encode('utf-8'), (self.splunk_ip, self.splunk_port))
              
              #print( data )
           
       
    
##################################################    




 
test_rover = snmp_rover_get_data (
     "172.8.2.68",
     ["1.3.6.1.4.1.19324.2.2.1.3.4.7.3.3.1.5." + "1" + ".1","1.3.6.1.4.1.19324.2.2.1.3.4.7.3.3.1.5." + "1" + ".2"],
     "sdsd sds",
     1
     )

   




################new#############
rover_host= []
rover_tipo = []
rover_slot = []
rover_get_snmp = []
with open('rovers_mfe_programas.csv', 'r', newline='\n') as csvfile:
     reader = csv.DictReader(csvfile)
     for row in reader:
          try : 
               if ipaddress.IPv4Address( str(row ["host"]) ).version == 4  :
                   slot=0
                   for slot in range (4):
                        slot += 1
                        
                        ##tarjeta asi ip
                        if row ["slot" + str (slot)+ "-tarjeta-tipo"] == "ASI <-> IP Gateway" :
                              print ( row ["host"] + " : ASI <-> IP Gateway " + str(slot)  )
                              if row ["slot" + str (slot) + "-asi-ip-mode"] == "Decapsulador" : 
                                   print ("modo Decapsulador cheque eth1 y eth2 bitrate")
                                   rover_oid = ["1.3.6.1.4.1.19324.2.2.1.3.4.7.3.3.1.5." + str(slot) + ".1","1.3.6.1.4.1.19324.2.2.1.3.4.7.3.3.1.5." + str(slot) + ".2"]
                                   print (rover_oid)
                                   rover_host.append( row ["host"] )
                                   rover_tipo.append( row ["slot" + str (slot)+ "-tarjeta-tipo"] )
                                   rover_slot.append(  str (slot)  )
                                   rover_get_snmp.append ( rover_oid ) 
                                   
                        ##tarjeta dtmb
                        if row ["slot" + str (slot)+ "-tarjeta-tipo"] == "DTMB CUBA" :
                              print ( row ["host"] + " : DTMB SLOT " + str(slot)  )
                              
                             

                              rover_oid = ["1.3.6.1.4.1.19324.2.2.1.3.2.2.3.1.1.5." + str(slot),"1.3.6.1.4.1.19324.2.2.1.3.2.2.3.1.1.7." + str(slot)]
                              #print (rover_oid)
                              rover_host.append( row ["host"] )
                              rover_tipo.append( row ["slot" + str (slot)+ "-tarjeta-tipo"] )
                              rover_slot.append(  str (slot)  )
                              rover_get_snmp.append ( rover_oid )
                                       
                        ##tarjeta satelital
                        if row ["slot" + str (slot)+ "-tarjeta-tipo"] == "DVB-S/DVB-S2 32APSK" :
                              print ( row ["host"] + " : SATELITAL SLOT " + str(slot)  )
                             
                              
                              rover_oid = ["1.3.6.1.4.1.19324.2.2.1.3.2.1.3.1.1.7." + str(slot),"1.3.6.1.4.1.19324.2.2.1.3.2.1.3.1.1.9." + str(slot)]
                              #print (rover_oid)
                              rover_host.append( row ["host"] )
                              rover_tipo.append( row ["slot" + str (slot)+ "-tarjeta-tipo"] )
                              rover_slot.append(  str (slot)  )
                              rover_get_snmp.append ( rover_oid )
                             
                              
          except:
               print ( "<" +  row ["host"] + ">")




#######






class Worker(threading.Thread):
    def __init__(self, host , oid, tipo, slot):
        threading.Thread.__init__(self)
        self.rover = snmp_rover_get_data( host , oid, tipo, slot)
        self.setDaemon(True)
        self.start()
        

    def run(self):
         while True:
             self.rover.get()
             
            
                       
           
           
hilos = []
for k in range ( len (rover_host )) :
       hilos.append( Worker (  rover_host[k] , rover_get_snmp [k],rover_tipo[k],rover_slot [k]) )
  


while   True:
    sleep(1)          

                   
           

     
       
