/**********************************************************************
 * file:  sr_router.c
 *
 * Descripción:
 *
 * Este archivo contiene todas las funciones que interactúan directamente
 * con la tabla de enrutamiento, así como el método de entrada principal
 * para el enrutamiento.
 *
 **********************************************************************/

#include <netinet/in.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Inicializa el subsistema de enrutamiento
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    assert(sr);

    /* Inicializa la caché y el hilo de limpieza de la caché */
    sr_arpcache_init(&(sr->cache));

    /* Inicializa los atributos del hilo */
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    /* Hilo para gestionar el timeout del caché ARP */
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */

struct sr_rt* sr_encontrar_entrada(struct sr_instance* sr, uint32_t dst_ip) {
    struct sr_rt* actual = sr->routing_table;
    struct sr_rt* mejor = NULL;
    uint32_t mejor_mask = 0;

    while (actual) {
        uint32_t mask = ntohl(actual->mask.s_addr);
        uint32_t red  = ntohl(actual->dest.s_addr);
        if ((ntohl(dst_ip) & mask) == red && mask >= mejor_mask) {
            mejor = actual;
            mejor_mask = mask;
        }
        actual = actual->next;
    }
    return mejor;
}

/* CUSTOM : Envia un paquete ICMP Echo Reply */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{

    /* Busco en routing table el mejor match para ipDst */
    struct sr_rt *rt = sr_encontrar_entrada(sr, ipDst);

    /* sin ruta */
    if (!rt) { 
      fprintf(stderr, "sr_send_icmp_error_packet: no route to %u\n", ntohl(ipDst));
      print_addr_ip_int(ipDst);
      return;
    }  

    /* elijo next_hop */
    uint32_t next_hop = (rt -> gw.s_addr !=0)? rt -> gw.s_addr : ipDst;
    struct sr_if *iface = sr_get_interface(sr, rt->interface);
    
    /* si no hay interfaz de salida */
    if (!iface) {
      fprintf(stderr, "sr_send_icmp_error_packet: interface %s not found\n", rt->interface);
      return;
    }

    /* mapeo de ipPacket in */
    sr_ethernet_hdr_t *eth_in = (sr_ethernet_hdr_t *)ipPacket;
    sr_ip_hdr_t *ip_in = (sr_ip_hdr_t *)(ipPacket + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp_in = (sr_icmp_t3_hdr_t *)((uint8_t *)ip_in + sizeof(sr_ip_hdr_t));

    uint16_t icmp_len = ntohs(ip_in->ip_len) - sizeof(sr_ip_hdr_t);
    uint32_t ip_total_len = sizeof(sr_ip_hdr_t) + icmp_len;
    uint32_t pkt_len = sizeof(sr_ethernet_hdr_t) + ip_total_len;

    /* nuevo packet out */
    uint8_t *packet = malloc(pkt_len);
    memset(packet, 0, pkt_len);

    sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp3 = (sr_icmp_t3_hdr_t*) ((uint8_t *)ip + sizeof(sr_ip_hdr_t));

    /* eth hdr */
    memcpy(eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
    memcpy(eth->ether_dhost, eth_in->ether_shost, ETHER_ADDR_LEN);
    eth->ether_type = htons(ethertype_ip);

    /* ip hdr */
    ip->ip_v  = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(ip_total_len);
    ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = INIT_TTL;
    ip->ip_p = ip_protocol_icmp;
    ip->ip_src = iface->ip;
    ip->ip_dst = ip_in->ip_src;
    ip->ip_sum = 0;

    /* icmp hdr y payload */
    memcpy(icmp3, icmp_in, icmp_len);
    icmp3->icmp_type = type; 
    icmp3->icmp_code = code;
    icmp3->unused = icmp_in->unused;
    icmp3->next_mtu = icmp_in->next_mtu;
    icmp3->icmp_sum = 0;

    /* Copy original IP header + first 8 bytes of payload into icmp data (menos en echo request/reply)*/
    if (type != 8 && type != 0) { 
      
      /* MEJORABLE PERO NO LO QUIERO HACER AHORA 
      
      sr_ip_hdr_t *ip_old = (sr_ip_hdr_t *)(ipPacket + sizeof(sr_ethernet_hdr_t));
      uint16_t orig_hdr_len = ip_old->ip_hl * 4;            
      uint16_t orig_total_len = ntohs(ip_old->ip_len);     
      uint16_t copy_len = orig_hdr_len + 8;                
      if (copy_len > orig_total_len) copy_len = orig_total_len;

      memcpy(icmp3->data, ip_old, copy_len); */

      memcpy(icmp3->data, ip_in, ICMP_DATA_SIZE);
    }

    /* Checksums */
    icmp3->icmp_sum = icmp3_cksum(icmp3, icmp_len);
    ip->ip_sum = ip_cksum(ip, sizeof(sr_ip_hdr_t));

    printf("pedro pica\n");
    /* Buscar entrada ARP para next_hop */
    struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), next_hop);
    if (entry) {
      /* ARP en la cache */
      memcpy(eth->ether_dhost, entry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, pkt_len, iface->name);
      free(entry);
      free(packet);
    } else {
      /* No hay MAC en la cache: encolar para request ARP */
      struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop, packet, pkt_len, iface->name);
      handle_arpreq(sr, req);
      free(packet);
    }
}

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

    sr_ip_hdr_t *hdr_ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    print_hdrs(packet, len);

    /* ver si la iface dst es del sr */
    struct sr_if *found_if = sr_get_interface_given_ip(sr, hdr_ip -> ip_dst);

    if (!found_if)      /* no es iface del sr */ 
    {
        /* TTL muere */
        if (hdr_ip->ip_ttl <= 1) 
        {
            sr_send_icmp_error_packet(11, 0, sr, hdr_ip->ip_src, packet);      /* estaba err aca tmb */
            return;
        }

        hdr_ip->ip_ttl--;
        hdr_ip->ip_sum = 0;
        hdr_ip->ip_sum = cksum(hdr_ip, sizeof(sr_ip_hdr_t));    /* recalculo cambio ttl */

        /* reenvio */

        /* rezo pq este bien ese codigo :) */
        struct sr_rt *entrada = sr_encontrar_entrada(sr, hdr_ip -> ip_dst);
        if (!entrada) return; /* ni idea gg */

        /* prefiero gateway */
        uint32_t next_hop = (entrada -> gw.s_addr !=0)? entrada -> gw.s_addr : hdr_ip -> ip_dst;

        struct sr_if *iface_salida = sr_get_interface(sr, entrada -> interface);
        if (!iface_salida) return;  /* ggs */

        /* busco en cache mac del nexthop */
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr -> cache, next_hop);
        if (!arp_entry)     
        {
            /* mando arp */
            sr_arpcache_queuereq(&sr -> cache, next_hop, packet, len, iface_salida -> name);
            return;     
        }

        /* en cache */
        /* cambio direcciones eth para next hop */
        memcpy(eHdr->ether_dhost, arp_entry -> mac, ETHER_ADDR_LEN);      
        memcpy(eHdr->ether_shost, iface_salida -> addr, ETHER_ADDR_LEN);  

        sr_send_packet(sr, packet, len, iface_salida -> name);
        free(arp_entry);
        
        return; /* FALTABA ESTE RETURN DEL DIABLO POR ESO HABIAN DUPLICATES */
    }
    /* es para iface sr */

    uint8_t protocol = hdr_ip -> ip_p;     

    if (protocol == ip_protocol_icmp)   
    {
        /* check creo q bien */
        sr_icmp_hdr_t *hdr_icmp = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* check checksum xd */
        int icmp_len = len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if (icmp_cksum(hdr_icmp, icmp_len) != hdr_icmp -> icmp_sum) return;     /* checksum mal */

        /* Echo Req */
        if ( hdr_icmp -> icmp_type == 8 && hdr_icmp -> icmp_code == 0)       
        {     
            sr_send_icmp_error_packet(0, 0, sr, hdr_ip -> ip_src, packet);   /* Echo Reply */
        }                                      
        return;
    } 
    else if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)   
    {
        sr_send_icmp_error_packet(3, 3, sr, hdr_ip -> ip_src, packet);   /* port unreachable */
    }

    return;
}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,               
        uint8_t *destAddr,              /* broadcast */
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
  /*
  
  SUGERENCIAS:
  - Verifique si se trata de un ARP request o ARP reply 
  - Si es una ARP request, antes de responder verifique si el mensaje consulta por la dirección MAC asociada a una dirección IP configurada en una interfaz del router
  - Si es una ARP reply, agregue el mapeo MAC->IP del emisor a la caché ARP y envíe los paquetes que hayan estado esperando por el ARP reply

  */

  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) return;   /* lil paqueton */

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));  /*skippeo eth hdr*/

  uint16_t op_code = ntohs(arp_hdr -> ar_op);

  if (op_code == arp_op_request)  
  {
    struct sr_if* found_if = sr_get_interface_given_ip(sr, arp_hdr -> ar_tip);  /* busco IP iface en sr */

    if (!found_if) return;  /* iface no del sr ignore nashi ? */

    /* construyo packet arp reply con mapping */
    int arpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *new_arpPacket = malloc(arpPacketLen);

    sr_ethernet_hdr_t *new_eth_hdr = (struct sr_ethernet_hdr *) new_arpPacket;
    memcpy(new_eth_hdr->ether_dhost, srcAddr, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, found_if -> addr, sizeof(uint8_t) *ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = htons(ethertype_arp);

    sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *) (new_arpPacket + sizeof(sr_ethernet_hdr_t));
    new_arp_hdr->ar_hrd = htons(1);
    new_arp_hdr->ar_pro = htons(2048);
    new_arp_hdr->ar_hln = 6;
    new_arp_hdr->ar_pln = 4;
    new_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(new_arp_hdr->ar_sha, found_if -> addr, ETHER_ADDR_LEN);
    memcpy(new_arp_hdr->ar_tha, srcAddr, ETHER_ADDR_LEN);
    new_arp_hdr->ar_sip = found_if -> ip;    
    new_arp_hdr->ar_tip = arp_hdr -> ar_sip;

    /* send arp reply */
    sr_send_packet(sr, new_arpPacket, arpPacketLen, found_if -> name);

    free(new_arpPacket);
  }
  else if (op_code == arp_op_reply) 
  {
    /* agregar mappeo MAC -> IP a la cache ARP */
    struct sr_arpreq *pend_entry = sr_arpcache_insert(&(sr -> cache), arp_hdr -> ar_sha, arp_hdr -> ar_sip);

    if (pend_entry != NULL)     /* pkts estaban esperando por el arp reply */
    {
      struct sr_packet *pkt = pend_entry -> packets;
      while (pkt != NULL)
      {
        /* casteo pkt in */
        sr_ethernet_hdr_t *eth_in = (sr_ethernet_hdr_t *)pkt -> buf;
        sr_ip_hdr_t *ip_in = (sr_ip_hdr_t *)(pkt -> buf + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *icmp_in = (sr_icmp_t3_hdr_t *)((uint8_t *)ip_in + sizeof(sr_ip_hdr_t));

        print_hdrs(pkt -> buf, pkt -> len);

        /* cambio direcciones eth para next hop */
        memcpy(eth_in->ether_dhost, arp_hdr -> ar_sha, ETHER_ADDR_LEN);      
        struct sr_if* salida_if = sr_get_interface(sr, pkt -> iface);
        memcpy(eth_in->ether_shost, salida_if -> addr, ETHER_ADDR_LEN);

        /* send req */
        sr_send_packet(sr, pkt -> buf , pkt -> len, pkt -> iface);
        pkt = pkt -> next;
      }
      /* chau entry */
      sr_arpreq_destroy(&(sr -> cache), pend_entry);
    }
  }
  else {
    /* full error opcode no existe? */
  }

}

/* 
* ***** A partir de aquí no debería tener que modificar nada ****
*/

/* Envía todos los paquetes IP pendientes de una solicitud ARP */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface) {

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL) {
     ethHdr = (sr_ethernet_hdr_t *) currPacket->buf;
     memcpy(ethHdr->ether_shost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
     memcpy(ethHdr->ether_dhost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);

     copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
     memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

     sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
     free(copyPacket);
     currPacket = currPacket->next;
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */
