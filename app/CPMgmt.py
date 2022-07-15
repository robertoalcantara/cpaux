# coding: utf-8

import http.client
import json
import ssl
from collections import defaultdict
    
class CPObject(object):
    """
    Classe de objeto generico do Checkpoint.
    Vários outros objetos herdam dessa classe.
    """
    uid = None
    name = ""
    def __init__(self, uid, name):
        self.uid = uid;
        self.name = name
        
    def __str__(self):
        return( str( [self.uid, self.name] ) )
    def toJSON(self, indent=False):
        if indent :
            return json.dumps(self, default=lambda o: o.__dict__, indent=4)
        else:
            return json.dumps(self, default=lambda o: o.__dict__)

class CPSecurityZone(CPObject):
    """
    Exemplo json: {'uid': '8c4041ea-ff14-4e4b-a9d9-4183d18c790a', 'name': 'DMZZone', 'type': 'security-zone', 
        'domain': {'uid': 'a0bbbc99-adef-4ef8-bb6d-defdefdefdef', 'name': 'Check Point Data', 'domain-type': 'data domain'
    """
    def __init__(self, uid, name):
        super().__init__(uid, name)

class CPUserGroup(CPObject):
    """
    Exemplo json: {'uid': '83861b69-453c-4f9a-bd75-20c1a2394e9e', 'name': 'grp_suporte', 'type': 'user-group', 
        'domain': {'uid': '41e821a0-3720-11e3-aa6e-0800200c9fde', 'name': 'SMC User', 'domain-type': 'domain'}}
    """
    def __init__(self, uid, name):
        super().__init__(uid, name)
        
class CPGroup(CPObject):
    """
    Exemplo json: {'uid': 'd7aef5ca-d40f-4b77-b049-cc702b997617', 'name': 'grp_tst_clientes_k8s', 'type': 'group', 
        'domain': {'uid': '41e821a0-3720-11e3-aa6e-0800200c9fde', 'name': 'SMC User', 'domain-type': 'domain'}}
    """
    def __init__(self, uid, name):
        super().__init__(uid, name)
        self.content = {}

    def addContent(self, obj):
        self.content[ obj.uid ] = obj


class CPGroupWithExclusion(CPObject):
    """
    Exemplo json: {'uid': 'bc3bbd67-fa79-407d-929e-330e4453db8d', 'name': 'INTERNET', 'type': 'group-with-exclusion', 
        'domain': {'uid': '41e821a0-3720-11e3-aa6e-0800200c9fde', 'name': 'SMC User', 'domain-type': 'domain'}}
    """
    def __init__(self, uid, name):
        super().__init__(uid, name)

class CPAccessRole(CPObject):
    """
    Exemplo json: {'uid': 'eb7a59a0-e784-4102-8919-0582fbf3baf7', 'name': 'access_role_usuario_seguranca', 'type': 'access-role', 
        'domain': {'uid': '41e821a0-3720-11e3-aa6e-0800200c9fde', 'name': 'SMC User', 'domain-type': 'domain'}}
    """
    def __init__(self, uid, name):
        super().__init__(uid, name)

class CPServiceGroup(CPObject):
    """
    Exemplo json: {'uid': '4c3e148f-bcc4-4c97-9955-09da850fb9a6', 'name': 'Hotline', 'type': 'service-group', 
        'domain': {'uid': 'a0bbbc99-adef-4ef8-bb6d-defdefdefdef', 'name': 'Check Point Data', 'domain-type': 'data domain'}}
    """
    def __init__(self, uid, name):
        super().__init__(uid, name)

class CPDnsDomain(CPObject):
    """
    Exemplo json: {'uid': 'fec7670e-677e-4239-a28b-98a6b0c6f757', 'name': '.a.rtmp.youtube.com', 'type': 'dns-domain', 
        'domain': {'uid': '41e821a0-3720-11e3-aa6e-0800200c9fde', 'name': 'SMC User', 'domain-type': 'domain'}}
    """
    def __init__(self, uid, name):
        super().__init__(uid, name)
        
class CPUpdateableObject(CPObject):
    """
    Exemplo json: {'uid': 'c8e946a1-62bc-405c-a2f5-721eff2526ea', 'name': 'Brazil', 'type': 'updatable-object', 
        'domain': {'uid': '41e821a0-3720-11e3-aa6e-0800200c9fde', 'name': 'SMC User', 'domain-type': 'domain'}}
    """
    def __init__(self, uid, name):
        super().__init__(uid, name)

class CPHost(CPObject): 
    """
    Classe que representa um host no Checkpoint. 
    #TODO: v6 não testado.
    """
    def __init__(self, uid, name, ipv4_addr=None, ipv6_addr=None):
        super().__init__(uid, name)
        self.ipv4_addr = ipv4_addr
        self.ipv6_addr = ipv6_addr
        
    def __str__(self):
        return( str( [self.uid, self.name, self.ipv4_addr, self.ipv6_addr] ) )

class CPAddressRange(CPObject): 
    """
    Classe que representa uma faixa de endereços. 
    Exemplo json:  type': 'address-range', 'ipv4-address-first': '0.0.0.0', 'ipv4-address-last': '255.255.255.255'}
    """
    def __init__(self, uid, name, ipv4_addr_first=None, ipv4_addr_last=None, ipv6_addr_first=None, ipv6_addr_last=None):
        super().__init__(uid, name)
        self.ipv4_addr_first = ipv4_addr_first
        self.ipv4_addr_last = ipv4_addr_last
        self.ipv6_addr_first = ipv6_addr_first
        self.ipv6_addr_last = ipv6_addr_last
        
    def __str__(self):
        return( str( [self.uid, self.name, self.ipv4_addr_first, self.ipv4_addr_last, self.ipv6_addr_first, self.ipv6_addr_last] ) )
        
class CPNetwork(CPObject): 
    """
    Classe que representa uma rede IP
    Exemplo json: #{'uid': '2cdf9995-0fd8-4908-9314-4d68fefacd2e', 'name': 'cef_conectividade_social', 
        'type': 'network', 'subnet4': '200.201.174.0', 'mask-length4': 24, 'subnet-mask': '255.255.255.0'}
    """
    def __init__(self, uid, name, subnet4=None, mask_length4=None, subnet_mask=None,  subnet6=None, mask_length6=None):
        super().__init__(uid, name)
        self.subnet4 = subnet4
        self.mask_length4 = mask_length4
        self.subnet_mask = subnet_mask
        self.subnet6 = subnet6
        self.mask_length6 = mask_length6
        
    def __str__(self):
        return( str( [self.uid, self.name, self.subnet4, self.mask_length4, self.subnet_mask, self.subnet6, self.mask_length6] ) )

class CPService(CPObject):
    """
    Classe que representa um serviço
    Exemplo json: {'uid': '97aeb427-9aea-11d5-bd16-0090272ccb33', 'name': 'H323_any', 'type': 'service-tcp', 
        'domain': {'uid': 'a0bbbc99-adef-4ef8-bb6d-defdefdefdef', 'name': 'Check Point Data', 'domain-type': 'data domain'}, 'port': '1720'}
    """
    def __init__(self, uid, name, type=None, port=None):
        super().__init__(uid, name)
        self.type = type #"tcp-type", "udp-type" : Checkpoint sintax
        self.port = port 

    def __str__(self):
        return( str( [self.uid, self.name, self.type, self.port] ) )


class CPRule(CPObject):
    """
    Classe que representa uma regra expecífica no CP.
    """
    def __init__(self, uid, name, rule_number, src={}, src_negate=False, dst={}, dst_negate=False, dst_svc={}, last_modifier="",
             last_modify= "", additional_info="", ticket_number="", ticket_requester="", action="", enabled=True):
        
        super().__init__(uid, name)
        self.number = rule_number
        self.sources = src
        self.sources_negate = False
        self.destinations = dst
        self.destinations_negate = False
        self.services = dst_svc
        self.last_modifier = last_modifier
        self.last_modify = last_modify
        self.action = action
        self.enabled = enabled
        self.additional_info = additional_info
        self.ticket_number = ticket_number
        self.ticket_requester = ticket_requester
        
    def addSource(self, src):
        self.source[src.uid] = src
    def addDestination(self, dst):
        self.destination[dst.uid] = dst
 
class CPRulebase(CPObject):
    """
    Classe que representa um conjunto de regras no CP.
    """
    def __init__(self, uid, name ):
        super().__init__(uid, name)
        self.rules = {}
        
    def addRule(self, rule):
        self.rules[ rule.uid ] = rule

class CPApi(object):

    def __init__(self, mgmt_server, api_key, noSSL=False, rulebases_names=[]):
        """Construtor
        :param mgmt_server: IP servidor
        :param api_key: API key
        :param noSSL: disable SSl check
        :param rulebases: rulebases de interesse
        """
        self.api_key = api_key
        self.mgmt_server = mgmt_server
        self.noSSL = noSSL

        self.sid = None
        
        self.rulebases = {} #indice pela rulebase
        self.rulebases_names = rulebases_names
                
        self.services = {} #indice por uid
        self.hosts = {} #indice por uid
        self.securityZones = {}
        self.userGroups = {}
        self.groups = {}
        self.groupsWithExclusion = {}
        self.accessRoles = {}
        self.serviceGroups = {}
        self.dnsDomains = {}
        self.serviceGroups = {}
        self.serviceGroups = {}
        self.addressRanges = {}
        self.updatableObjects = {}
        self.networks = {}
        
        self.__login()

        #objeto ANY no CP nao é listado qdo pegamos todos os objetos.
        #workarround até descobrir onde fica escondido.
        any_object_id = '97aeb369-9aea-11d5-bd16-0090272ccb30' 
        self.updatableObjects[any_object_id] = CPObject(any_object_id, "ANY")
        
        self.__fillObjects()
        self.__fillRules()
        
    def __login(self):
        try:
            payload = json.dumps( { "api-key": self.api_key } )
            data = self.__queryCp("/web_api/login", payload )
            self.sid = data['sid']
        except KeyError:
            print( data['message'] )
            exit(1)
        
    def __fillRules(self, only_enabled=True):
        """
        Varre o conjunto de regras, cria os rulebases e popula com rules.
        As rulebases de interesse são passadas em uma lista no momento da criação do objeto de conexão
        param only_enabled : filtra as regras

        """
        for rulebase_name in self.rulebases_names:
            offset = 0
            payload = json.dumps( { "limit" : "500", "name" : rulebase_name , "offset" : offset } )
            data = self.__queryCp("/web_api/show-access-rulebase", payload )
            uid = data['uid']
            rulebase = data['rulebase']
            self.rulebases[uid] = CPRulebase(uid, rulebase_name)
            
            rules = self.__parseRulebase(rulebase)
            
            for rule in rules:

                if only_enabled and not rule['enabled']: continue 

                source = {}
                for src_uid in rule['source']:
                    obj = self.searchUid( src_uid )
                    if obj == None:
                        print(" Rule name: " + rule['name'] + " number: " + str(rule['rule-number'])    )
                        raise Exception("Objeto nao incluso no parser foi usado. Verifique o tipo do objeto e adicione: " + src_uid)
                    source[src_uid] = obj
                    if type(obj) == CPGroup:
                        self.__fillGroups(obj.uid)
                    
                destination = {}
                for dst_uid in rule['destination']:
                    obj = self.searchUid( dst_uid )
                    if obj == None:
                        print(" Rule name: " + rule['name'] + " number: " + str(rule['rule-number'])    )
                        raise Exception("Objeto nao incluso no parser foi usado. Verifique o tipo do objeto e adicione: " + dst_uid)
                    destination[dst_uid] = obj
                    if type(obj) == CPGroup:
                        self.__fillGroups(obj.uid)
                try:
                    name = rule['name']    
                except KeyError:
                    name = ""
                    
                services = {}
                for svc_uid in rule['service']:
                    obj = self.searchUid( svc_uid )
                    services[svc_uid] = obj

                self.rulebases[uid].addRule( CPRule( rule['uid'], name, rule['rule-number'], source, rule['source-negate'], destination, rule['destination-negate'], 
                    services, rule['meta-info']['last-modifier'], rule['meta-info']['last-modify-time']['iso-8601'],
                    rule['custom-fields']['field-1'], rule['custom-fields']['field-2'], rule['custom-fields']['field-3'] , "", rule['enabled'] ) )

        self.additional_info = ""
        self.ticket_number = ""
        self.ticket_requester = ""

    def __parseRulebase(self, rulebase_json):
        """
        Recebe o json de uma rulebase e extrai todas as regras do rulebase e  eventuais sub-rulebases (access-sessions possuem rulebases)
        """
        rules_all = []
        for item in  rulebase_json:
            if item['type'] == 'access-section':
                rules_all = rules_all + ( self.__parseRulebase(item['rulebase'] ) ) #let's kill MISRA-C

            if item['type'] == 'access-rule':
                rules_all.append( item )
        return ( rules_all )
                    
    def searchUid(self, uid_search) :
        local_dict = { 'security-zone': self.securityZones, 'user-group': self.userGroups, 'group' : self.groups,
            'service-group' : self.serviceGroups,  'dns-domain' : self.dnsDomains, 'updatable-object' : self.updatableObjects, 
            'host' : self.hosts, 'service-tcp' : self.services, 'service-udp' : self.services, 'address-range' : self.addressRanges,
            'network' : self.networks, 'group-with-exclusion' : self.groupsWithExclusion, 'access_role' : self.accessRoles }
        for objs in local_dict:
            for item in local_dict[objs]: 
                if local_dict[objs][item].uid == uid_search:
                    return (local_dict[objs][item])
                
    def __fillObjects(self): 
        """
        Executa a query no Checkpoint management server e cria os objetos, populando o dicionario por tipo de objeto
        """
        offset = 0
        local_dict = { 'security-zone': self.securityZones, 'user-group': self.userGroups, 'group' : self.groups,
            'service-group' : self.serviceGroups,  'dns-domain' : self.dnsDomains, 'updatable-object' : self.updatableObjects, 
            'host' : self.hosts, 'service-tcp' : self.services, 'service-udp' : self.services, 'address-range' : self.addressRanges,
            'network' : self.networks, 'group-with-exclusion' : self.groupsWithExclusion,
            'access-role' : self.accessRoles }
            
        name_classes = {  'security-zone': CPSecurityZone,  'user-group': CPUserGroup, 'group' : CPGroup,
            'service-group' : CPServiceGroup, 'dns-domain' : CPDnsDomain, 'updatable-object' : CPUpdateableObject, 
            'host' : CPHost, 'service-tcp' : CPService, 'service-udp' : CPService, 'address-range' : CPAddressRange,
            'network' : CPNetwork, 'group-with-exclusion' : CPGroupWithExclusion,
            'access-role' : CPAccessRole }
        
        for objtype in name_classes:
            offset = 0
            while True:
                payload = json.dumps( { "limit" : "500", "type" : objtype , "offset" : offset } )
                data = self.__queryCp("/web_api/show-objects", payload )

                for ob in data['objects']:
                    #generic fields
                    uid = ob['uid']
                    local_dict[objtype][uid] = name_classes[objtype](uid, ob['name'])
                        
                    #specific fields
                    if (objtype=='host'):
                        local_dict[objtype][uid].ipv4_addr = ob['ipv4-address']
                   
                    if (objtype=='service-udp' or objtype=='service-tcp'):
                        local_dict[objtype][uid].type = objtype
                        local_dict[objtype][uid].port = ob['port']
                    
                    if (objtype=='address-range'):
                        try:
                            local_dict[objtype][uid].ipv4_addr_first = ob['ipv4-address-first']
                            local_dict[objtype][uid].ipv4_addr_last  = ob['ipv4-address-last']
                        except KeyError:
                            local_dict[objtype][uid].ipv6_addr_first = ob['ipv6-address-first']
                            local_dict[objtype][uid].ipv6_addr_last  = ob['ipv6-address-last']
                    if (objtype=='network'):
                        try:
                            local_dict[objtype][uid].subnet_mask = ob['subnet-mask']
                            local_dict[objtype][uid].subnet4 = ob['subnet4']
                            local_dict[objtype][uid].mask_length4 = ob['mask-length4']
                        except KeyError:
                            local_dict[objtype][uid].subnet4 = ob['subnet6']
                            local_dict[objtype][uid].mask_length6 = ob['mask-length6']

                        
                if (len( data['objects'] ) < 500):
                    break
                offset = offset + 500                

    def __fillGroups(self, uid):
        '''
        Os grupos nao trazem os atributos, requerem chamadas especificas. 
        NAO vamos preencher todos os objetos, apenas os necessarios. muito caro.
        Aparentemente versoes novas da API melhoraram isso.
        '''
        #for grp in self.groups.values():
        payload = json.dumps( { "uid" : uid } )
        data = self.__queryCp("/web_api/show-group", payload )
        grp = self.searchUid( data['uid'] )
        for ob in data['members']:
           #print (ob)
           grp.addContent( self.searchUid( ob['uid'] ) ) 

    def __queryCp(self, url, payload):
        if self.noSSL:
            conn = http.client.HTTPSConnection( self.mgmt_server, context = ssl._create_unverified_context())
        else:
            conn = http.client.HTTPSConnection( self.mgmt_server )
        if self.sid == None:
            headers = { 'Content-Type': 'application/json' }
        else:
            headers = { 'Content-Type': 'application/json', 'X-chkp-sid': self.sid }
 
        conn.request("POST", url, payload, headers)
        res = conn.getresponse()
        data = res.read()
        return( json.loads(data) )




if __name__ == "__main__":

    # debug
    print("debug test")

    f = open('.key.txt')
    key = f.read()
    f.close()
    
    server = "192.168.0.100"
    #cp = CPApi(server, key, noSSL=True, rulebases_names=['inside_access_in_opt'])
    
    cp = CPApi(server, key, noSSL=True, rulebases_names=['dmz_access_in_opt'])
    
    #dump das regras
    for rulebase in cp.rulebases.values():
        for rule in rulebase.rules.values():
            print("\nRule:")
            print( rule )
            print( "Src:" )
            for source in rule.sources.values():
                print (source)
                if (type(source) == CPGroup):
                    print( "GRUPO ")
                    for obj in source.content.values():
                        print(obj)

            print( "Src negate: " + str(rule.sources_negate) )    
            print( "Dst:" )
            for dst in rule.destinations.values():
                print (dst)
            print( "Dst negate: " + str(rule.destinations_negate) )
            print( "Services:" )
            for svc in rule.services.values():
                print (svc)

            break # BREAK

    #busca de objeto
    #r = cp.searchUid('e2b578ac-5661-474c-b078-4b7473bf67a7')
    #print(type(r))
    #print(r)

    #dump dos objetos
    '''for s in cp.services:
        print (s)'''
    #print ( cp.services['1800a9a3-9837-436f-a587-04c662bce009'] )

    #print (len ( cp.hosts ) )
    for h in cp.hosts:
        print (cp.hosts[h])
    #print ( cp.hosts['72ace8c8-590c-4b32-801f-93a7664763a8'] )'''

    '''local_dict = { 'security-zone': cp.securityZones, 'user-group': cp.userGroups, 'group' : cp.groups,
                'service-group' : cp.serviceGroups,  'dns-domain' : cp.dnsDomains, 'updatable-object' : cp.updatableObjects,
                'address-range' : cp.addressRanges,  'network' : cp.networks, 'hosts' : cp.hosts, 'services' : cp.services  }
    for objs in local_dict:
        print("")
        print( objs )
        for item in local_dict[objs]:
            print ('\t' + local_dict[objs][item].__str__())'''
            

    
      
  