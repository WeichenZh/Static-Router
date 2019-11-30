/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
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
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

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
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* TODO: FILL IN YOUR CODE HERE */
  uint8_t buffer[1500];
  unsigned int sent_pkg_len=0;

  sr_ethernet_hdr_t   *sr_eth_header, *sr_eth_pkg_hdr; //in old version, it's not a pointer
  sr_icmp_t3_hdr_t    *sr_icmp_t3_pkg_hdr;
  sr_icmp_hdr_t       *sr_icmp_header, *sr_icmp_pkg_hdr;
  sr_arp_hdr_t        *sr_arp_header, *sr_arp_pkg_hdr; //in old version, it's not a pointer
  sr_ip_hdr_t         *sr_ip_header, *sr_ip_pkg_hdr;
  struct sr_if        *sr_pkg_if;

  enum sr_ethertype sr_eth_type;
  enum sr_arp_opcode sr_arp_op;

  sr_eth_header = (sr_ethernet_hdr_t *)packet;
  sr_eth_type = ntohs(sr_eth_header->ether_type);

  sr_pkg_if = sr_get_interface(sr, interface);

  switch (sr_eth_type)
  {
    case ethertype_arp:
    /*if it's arp packet*/
    {
      sr_arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      sr_arp_op = ntohs(sr_arp_header->ar_op);

      /* if its target ip is not the router, ignore it*/
      if (!sr_get_interface_by_ip(sr, sr_arp_header->ar_tip))
        break;

      switch (sr_arp_op)
      {
        /*request arp packet*/
        case arp_op_request:
        {
          /*set ethernet header*/
          sr_eth_pkg_hdr = (sr_ethernet_hdr_t *)buffer;
          memcpy(sr_eth_pkg_hdr->ether_dhost, sr_arp_header->ar_sha, ETHER_ADDR_LEN);
          memcpy(sr_eth_pkg_hdr->ether_shost, sr_pkg_if->addr, ETHER_ADDR_LEN);
          sr_eth_pkg_hdr->ether_type = htons(0x0806);

          /*set arp header*/
          sr_arp_pkg_hdr = (sr_arp_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t));
          sr_arp_pkg_hdr->ar_hrd = htons(0x0001);
          sr_arp_pkg_hdr->ar_pro = sr_arp_header->ar_pro;
          sr_arp_pkg_hdr->ar_hln = 6;
          sr_arp_pkg_hdr->ar_pln = 4;
          sr_arp_pkg_hdr->ar_op = htons(0x0002);
          sr_arp_pkg_hdr->ar_sip = sr_arp_header->ar_tip;
          sr_arp_pkg_hdr->ar_tip = sr_arp_header->ar_sip;
          memcpy(sr_arp_pkg_hdr->ar_sha, sr_pkg_if->addr, ETHER_ADDR_LEN);
          memcpy(sr_arp_pkg_hdr->ar_tha, sr_arp_header->ar_sha, ETHER_ADDR_LEN);

          //memcpy(buffer, (uint8_t *)&sr_eth_pkg_hdr, sizeof(sr_ethernet_hdr_t));
          //memcpy(buffer+sizeof(sr_ethernet_hdr_t), (uint8_t *)&sr_arp_pkg_hdr, sizeof(sr_arp_hdr_t));

          sent_pkg_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
          if (sr_send_packet(sr, buffer, sent_pkg_len, (const char *)interface) == -1)
            fprintf(stderr, "Error sending packet\n");

          break;
        } 
        /*reply arp packet*/
        case arp_op_reply:
        {
          struct sr_arpreq *req = NULL;

          req = sr_arpcache_insert(&(sr->cache), sr_arp_header->ar_sha, sr_arp_header->ar_sip);
          if(req)
          {
            struct sr_packet *pkg = NULL;
            for (pkg = req->packets;pkg !=NULL;pkg = pkg->next)
            {
              memcpy(buffer, pkg->buf, pkg->len);

              sr_eth_pkg_hdr = (sr_ethernet_hdr_t *)buffer;
              memcpy(sr_eth_pkg_hdr->ether_dhost, sr_arp_header->ar_sha, ETHER_ADDR_LEN);
              memcpy(sr_eth_pkg_hdr->ether_shost, sr_pkg_if->addr, ETHER_ADDR_LEN);
              sr_eth_pkg_hdr -> ether_type = htons(0x0800);

              sr_send_packet(sr, buffer, pkg->len, (const char *)interface);
            }

            sr_arpreq_destroy(&(sr->cache), req);
          }
          break;
        }
        default:
        {
          fprintf(stderr, "Unknown ARP packet type\n");
          break;
        }
      }
      break;
    }
    /*if it's ip packet*/
    case ethertype_ip:
    {
      sr_ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      
      // printf("dst_ip = \n");
      // print_addr_ip_int(ntohl(sr_ip_header->ip_dst));
      // printf("src_ip = \n");
      // print_addr_ip_int(ntohl(sr_ip_header->ip_src));
      // printf("ttl = %d\n", sr_ip_header->ip_ttl);

      /*if checksum is not valid*/
      if(check_checksum_ip(sr_ip_header, sizeof(sr_ip_hdr_t)) == -1)
        return;

      if (sr_get_interface_by_ip(sr, sr_ip_header->ip_dst) != 0)
      /*the packet is for the router*/
      {
        /*if the packet is icmp packet*/
        if(sr_ip_header->ip_p == ip_protocol_icmp)
        {
          sr_icmp_header = (sr_icmp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
          
          /*if the checksum is not valid, return*/
          if(check_checksum_icmp(sr_icmp_header, ntohs(sr_ip_header->ip_len)-sizeof(sr_ip_hdr_t)) == -1)
            return;

          /*if it is a echo request, encoding echo reply icmp packet*/
          if(sr_icmp_header->icmp_type == 0x08)
          {
            /*set ethernet header*/
            sr_eth_pkg_hdr = (sr_ethernet_hdr_t *)buffer;
            memcpy(sr_eth_pkg_hdr->ether_dhost, sr_eth_header->ether_shost, ETHER_ADDR_LEN);
            memcpy(sr_eth_pkg_hdr->ether_shost, sr_eth_header->ether_dhost, ETHER_ADDR_LEN);
            sr_eth_pkg_hdr->ether_type = htons(ethertype_ip);

            /*set ip header*/
            sr_ip_pkg_hdr = (sr_ip_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t));
            sr_ip_pkg_hdr->ip_hl = 5;
            sr_ip_pkg_hdr->ip_v = 4;
            sr_ip_pkg_hdr->ip_tos = 0;
            sr_ip_pkg_hdr->ip_len = sr_ip_header->ip_len;
            sr_ip_pkg_hdr->ip_id = htons(no_ip_id);
            sr_ip_pkg_hdr->ip_off = htons(0);
            sr_ip_pkg_hdr->ip_ttl = 64;
            sr_ip_pkg_hdr->ip_p = ip_protocol_icmp;
            sr_ip_pkg_hdr->ip_src = sr_ip_header->ip_dst;
            sr_ip_pkg_hdr->ip_dst = sr_ip_header->ip_src;
            sr_ip_pkg_hdr->ip_sum = 0;
            sr_ip_pkg_hdr->ip_sum = cksum(sr_ip_pkg_hdr, sizeof(sr_ip_hdr_t));

            no_ip_id++;

            /*set icmp packet*/
            sr_icmp_pkg_hdr = (sr_icmp_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
            memcpy(sr_icmp_pkg_hdr, sr_icmp_header, ntohs(sr_ip_header->ip_len)-sizeof(sr_ip_hdr_t));
            sr_icmp_pkg_hdr->icmp_type = 0;
            sr_icmp_pkg_hdr->icmp_code = 0;
            sr_icmp_pkg_hdr->icmp_sum = 0;
            sr_icmp_pkg_hdr->icmp_sum = cksum(sr_icmp_pkg_hdr, ntohs(sr_ip_header->ip_len)-sizeof(sr_ip_hdr_t));

            sr_send_packet(sr, buffer, len, (const char *)interface);
          }
        }
        /*if the packet for the router is not icmp packet, send icmp packet port unreachable*/
        else
        {
          struct sr_rt* next_hp = sr_by_LPM(sr, sr_ip_header->ip_src);
          struct sr_if* next_if = sr_get_interface(sr, (const char*)next_hp->interface);

          /*set ethernet header*/
          sr_eth_pkg_hdr = (sr_ethernet_hdr_t *)buffer;
          memcpy(sr_eth_pkg_hdr->ether_dhost, sr_eth_header->ether_shost, ETHER_ADDR_LEN);
          memcpy(sr_eth_pkg_hdr->ether_shost, sr_eth_header->ether_dhost, ETHER_ADDR_LEN);
          sr_eth_pkg_hdr->ether_type = htons(ethertype_ip);

          /*set ip header*/
          sr_ip_pkg_hdr = (sr_ip_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t));
          sr_ip_pkg_hdr->ip_hl = 5;
          sr_ip_pkg_hdr->ip_v = 4;
          sr_ip_pkg_hdr->ip_tos = 0;
          sr_ip_pkg_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
          sr_ip_pkg_hdr->ip_id = htons(no_ip_id);
          sr_ip_pkg_hdr->ip_off = htons(0);
          sr_ip_pkg_hdr->ip_ttl = 64;
          sr_ip_pkg_hdr->ip_p = ip_protocol_icmp;
          sr_ip_pkg_hdr->ip_src = next_if->ip;
          sr_ip_pkg_hdr->ip_dst = sr_ip_header->ip_src;
          sr_ip_pkg_hdr->ip_sum = 0;
          sr_ip_pkg_hdr->ip_sum = cksum(sr_ip_pkg_hdr, sizeof(sr_ip_hdr_t));

          no_ip_id++;

          /*set icmp packet*/
          sr_icmp_t3_pkg_hdr = (sr_icmp_t3_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
          sr_icmp_t3_pkg_hdr->icmp_type = 3;
          sr_icmp_t3_pkg_hdr->icmp_code = 3;
          sr_icmp_t3_pkg_hdr->unused = htons(0);
          sr_icmp_t3_pkg_hdr->next_mtu = htons(1500);
          memcpy(sr_icmp_t3_pkg_hdr->data, sr_ip_header, ICMP_DATA_SIZE);
          sr_icmp_t3_pkg_hdr->icmp_sum = 0;
          sr_icmp_t3_pkg_hdr->icmp_sum = cksum(sr_icmp_t3_pkg_hdr, sizeof(sr_icmp_t3_hdr_t));

          int ether_frame_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
          sr_send_packet(sr, buffer, ether_frame_len, (const char *)next_hp->interface);

          // print_hdr_eth(sr_eth_pkg_hdr);
          // print_hdr_ip(sr_ip_pkg_hdr);
          // print_hdr_icmp(sr_icmp_t3_pkg_hdr);
          // printf("%s\n", next_hp->interface);          
        }
      }
      else
      /*the packet is not for router and then send forward according to r_table*/
      {
        /*check the TTL*/
        if(sr_ip_header->ip_ttl <= 1)
        /*if ttl is less or equal to 1, send icamp that ttl is expired*/
        {
          struct sr_rt* next_hp = sr_by_LPM(sr, sr_ip_header->ip_src);
          struct sr_if* next_if = sr_get_interface(sr, (const char*)next_hp->interface);
          
          sr_eth_pkg_hdr = (sr_ethernet_hdr_t *)buffer;
          memcpy(sr_eth_pkg_hdr->ether_dhost, sr_eth_header->ether_shost, ETHER_ADDR_LEN);
          memcpy(sr_eth_pkg_hdr->ether_shost, sr_eth_header->ether_dhost, ETHER_ADDR_LEN);
          sr_eth_pkg_hdr->ether_type = htons(ethertype_ip);

          /*set ip header*/
          sr_ip_pkg_hdr = (sr_ip_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t));
          sr_ip_pkg_hdr->ip_hl = 5;
          sr_ip_pkg_hdr->ip_v = 4;
          sr_ip_pkg_hdr->ip_tos = 0;
          sr_ip_pkg_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
          sr_ip_pkg_hdr->ip_id = htons(no_ip_id);
          sr_ip_pkg_hdr->ip_off = htons(0);
          sr_ip_pkg_hdr->ip_ttl = 64;
          sr_ip_pkg_hdr->ip_p = ip_protocol_icmp;
          sr_ip_pkg_hdr->ip_src = next_if->ip;
          sr_ip_pkg_hdr->ip_dst = sr_ip_header->ip_src;
          sr_ip_pkg_hdr->ip_sum = 0;
          sr_ip_pkg_hdr->ip_sum = cksum(sr_ip_pkg_hdr, sizeof(sr_ip_hdr_t));

          no_ip_id++;

          /*set icmp packet, type 11 format is same with type 3*/
          sr_icmp_t3_pkg_hdr = (sr_icmp_t3_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
          sr_icmp_t3_pkg_hdr->icmp_type = 11;
          sr_icmp_t3_pkg_hdr->icmp_code = 0;
          sr_icmp_t3_pkg_hdr->unused = htons(0);
          sr_icmp_t3_pkg_hdr->next_mtu = htons(1500);
          memcpy(sr_icmp_t3_pkg_hdr->data, sr_ip_header, ICMP_DATA_SIZE);
          sr_icmp_t3_pkg_hdr->icmp_sum = 0;
          sr_icmp_t3_pkg_hdr->icmp_sum = cksum(sr_icmp_t3_pkg_hdr, sizeof(sr_icmp_t3_hdr_t));

          int ether_frame_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
          sr_send_packet(sr, buffer, ether_frame_len, (const char *)next_hp->interface);
        }
        else
        {
          struct sr_rt* next_hp = sr_by_LPM(sr, sr_ip_header->ip_dst);

          //print_addr_ip_int(ntohl(sr_ip_header->ip_dst));
          if(!next_hp)
          /*if not matching ip address, send dest net unreachable, type3, code 0*/
          {
            struct sr_rt* next_hp = sr_by_LPM(sr, sr_ip_header->ip_src);
            struct sr_if* next_if = sr_get_interface(sr, (const char*)next_hp->interface);
          
            sr_eth_pkg_hdr = (sr_ethernet_hdr_t *)buffer;
            memcpy(sr_eth_pkg_hdr->ether_dhost, sr_eth_header->ether_shost, ETHER_ADDR_LEN);
            memcpy(sr_eth_pkg_hdr->ether_shost, sr_eth_header->ether_dhost, ETHER_ADDR_LEN);
            sr_eth_pkg_hdr->ether_type = htons(ethertype_ip);

            /*set ip header*/
            sr_ip_pkg_hdr = (sr_ip_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t));
            sr_ip_pkg_hdr->ip_hl = 5;
            sr_ip_pkg_hdr->ip_v = 4;
            sr_ip_pkg_hdr->ip_tos = 0;
            sr_ip_pkg_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
            sr_ip_pkg_hdr->ip_id = htons(no_ip_id);
            sr_ip_pkg_hdr->ip_off = htons(0);
            sr_ip_pkg_hdr->ip_ttl = 64;
            sr_ip_pkg_hdr->ip_p = ip_protocol_icmp;
            sr_ip_pkg_hdr->ip_src = next_if->ip;
            sr_ip_pkg_hdr->ip_dst = sr_ip_header->ip_src;
            sr_ip_pkg_hdr->ip_sum = 0;
            sr_ip_pkg_hdr->ip_sum = cksum(sr_ip_pkg_hdr, sizeof(sr_ip_hdr_t));

            no_ip_id++;

            /*set icmp packet, type 11 format is same with type 3*/
            sr_icmp_t3_pkg_hdr = (sr_icmp_t3_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
            sr_icmp_t3_pkg_hdr->icmp_type = 3;
            sr_icmp_t3_pkg_hdr->icmp_code = 0;
            sr_icmp_t3_pkg_hdr->unused = htons(0);
            sr_icmp_t3_pkg_hdr->next_mtu = htons(1500);
            memcpy(sr_icmp_t3_pkg_hdr->data, sr_ip_header, ICMP_DATA_SIZE);
            sr_icmp_t3_pkg_hdr->icmp_sum = 0;
            sr_icmp_t3_pkg_hdr->icmp_sum = cksum(sr_icmp_t3_pkg_hdr, sizeof(sr_icmp_t3_hdr_t));

            int ether_frame_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
            sr_send_packet(sr, buffer, ether_frame_len, (const char *)next_hp->interface);
          }
          else
          {
            struct sr_if* next_if = sr_get_interface(sr, next_hp->interface);

            /*check if there is a mapping in cache*/
            struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache), next_hp->gw.s_addr);

            if(entry)
            {
              //printf(" i have the entry\n");
              memcpy(buffer, packet, len);
              sr_eth_pkg_hdr = (sr_ethernet_hdr_t *)buffer;

              memcpy(sr_eth_pkg_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
              memcpy(sr_eth_pkg_hdr->ether_shost, next_if->addr, ETHER_ADDR_LEN);
              sr_eth_pkg_hdr->ether_type = htons(ethertype_ip);

              sr_ip_pkg_hdr = (sr_ip_hdr_t *)(buffer+sizeof(sr_ethernet_hdr_t));
              sr_ip_pkg_hdr->ip_ttl -= 1;
              sr_ip_pkg_hdr->ip_sum = 0;
              sr_ip_pkg_hdr->ip_sum = cksum(sr_ip_pkg_hdr, sizeof(sr_ip_hdr_t));

              sr_send_packet(sr, buffer, len, next_hp->interface);
            }
            else
            /*no cache, then send arp packet five times*/
            {
              //printf("i have no entry\n");
              /*generate request packet*/
              struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), 
                next_hp->gw.s_addr, 
                packet, 
                len, 
                next_hp->interface);
              /*then we need to handle request*/

              handle_arpreq(req, sr);
            }
          }
        }
      }
      break;
    }
    default:
    {
      break;
    }
  }
}/* end sr_ForwardPacket */

/*dst_ip is raw ip address, which means binary form in network byte order */
struct sr_rt *sr_by_LPM(struct sr_instance *sr, uint32_t dst_ip)
{
  struct sr_rt *rt_cursor = NULL, *next_hp = NULL;
  uint32_t LP_mask=0;

  for (rt_cursor = sr->routing_table;rt_cursor!=NULL;rt_cursor = rt_cursor->next)
  {
    if(((dst_ip & rt_cursor->mask.s_addr)==rt_cursor->dest.s_addr) && (rt_cursor->mask.s_addr >= LP_mask))
    {
      next_hp = rt_cursor;
      LP_mask = rt_cursor->mask.s_addr;
    }
  }

  return next_hp;
}