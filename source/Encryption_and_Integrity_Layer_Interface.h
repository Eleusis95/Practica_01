/*
 * Encryption_and_Integrity_Layer_Interface.h
 *
 *  Created on: 6 feb. 2021
 *      Author: user
 */

#ifndef ENCRYPTION_AND_INTEGRITY_LAYER_INTERFACE_H_
#define ENCRYPTION_AND_INTEGRITY_LAYER_INTERFACE_H_

#include "aes.h" /*********AES Library*****/
#include "fsl_crc.h" /*****CRC Library****/
#include "tcpecho.h"/*****TCPE Library****/
#include "lwip/tcpip.h"
#include "netif/ethernet.h"
#include "enet_ethernetif.h"
#include "lwip/netifapi.h"
#include "lwip/sys.h"
#include "lwip/api.h"
#include "fsl_device_registers.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "lwip/opt.h"

/******IP definiciones**********/
/* Address of PHY interface. */
#define EXAMPLE_PHY_ADDRESS BOARD_ENET0_PHY_ADDRESS

/* System clock name. */
#define EXAMPLE_CLOCK_NAME kCLOCK_CoreSysClk


#ifndef EXAMPLE_NETIF_INIT_FN
/*! @brief Network interface initialization function. */
#define EXAMPLE_NETIF_INIT_FN ethernetif0_init
#endif /* EXAMPLE_NETIF_INIT_FN */


#endif /* ENCRYPTION_AND_INTEGRITY_LAYER_INTERFACE_H_ */
