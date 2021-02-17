/*
 * Encryption_and_Integrity_Layer_Config.h
 *
 *  Created on: 6 feb. 2021
 *      Author: user
 */

#ifndef ENCRYPTION_AND_INTEGRITY_LAYER_CONFIG_H_
#define ENCRYPTION_AND_INTEGRITY_LAYER_CONFIG_H_

#include "arch.h"

/* ****************************************************AES data****************************************************** */
static uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
static uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*****************************************************SW para interrupociones*****************************************/
extern volatile bool SWpress2; //Variable bool para guardar el estado logico si se presiono el SW2
extern volatile bool SWpress3;//Variable bool para guardar el estado logico si se presiono el SW3
/*******************************************************   IP    ******************************************************/
/* IP address configuration. */
#define configIP_ADDR0 192
#define configIP_ADDR1 168
#define configIP_ADDR2 1
#define configIP_ADDR3 100

/* Netmask configuration. */
#define configNET_MASK0 255
#define configNET_MASK1 255
#define configNET_MASK2 255
#define configNET_MASK3 0

/* Gateway address configuration. */
#define configGW_ADDR0 187
#define configGW_ADDR1 213
#define configGW_ADDR2 223
#define configGW_ADDR3 133

/* MAC address configuration. */
#define configMAC_ADDR                     \
    {                                      \
        0x02, 0x12, 0x13, 0x10, 0x15, 0x11 \
    }

/*****PORT*******/
#define PORT 7



#endif /* ENCRYPTION_AND_INTEGRITY_LAYER_CONFIG_H_ */
