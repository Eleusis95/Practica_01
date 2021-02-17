/*
 * Encryption_and_Integrity_Layer.c
 *
 *  Created on: 6 feb. 2021
 *      Author: user
 */

#include "Encryption_and_Integrity_Layer.h"

struct netconn *conn, *newconn;
uint8_t decrypted_msg[512] = {0};
uint8_t *toSend;
void Init_EncryptionAndIntegrity(){/*Condiciones iniciales*/

	 static struct netif netif;
	#if defined(FSL_FEATURE_SOC_LPC_ENET_COUNT) && (FSL_FEATURE_SOC_LPC_ENET_COUNT > 0)
	    static mem_range_t non_dma_memory[] = NON_DMA_MEMORY_ARRAY;
	#endif /* FSL_FEATURE_SOC_LPC_ENET_COUNT */
	    ip4_addr_t netif_ipaddr, netif_netmask, netif_gw;
	    ethernetif_config_t enet_config = {
	        .phyAddress = EXAMPLE_PHY_ADDRESS,
	        .clockName  = EXAMPLE_CLOCK_NAME,
	        .macAddress = configMAC_ADDR,
	#if defined(FSL_FEATURE_SOC_LPC_ENET_COUNT) && (FSL_FEATURE_SOC_LPC_ENET_COUNT > 0)
	        .non_dma_memory = non_dma_memory,
	#endif /* FSL_FEATURE_SOC_LPC_ENET_COUNT */
	    };

	    SYSMPU_Type *base = SYSMPU;
	    BOARD_InitPins();
	    BOARD_BootClockRUN();
	    BOARD_InitDebugConsole();

	    BOARD_InitGPIOInterrupts();
	    /* Disable SYSMPU. */
	    base->CESR &= ~SYSMPU_CESR_VLD_MASK;

	    IP4_ADDR(&netif_ipaddr, configIP_ADDR0, configIP_ADDR1, configIP_ADDR2, configIP_ADDR3);
	    IP4_ADDR(&netif_netmask, configNET_MASK0, configNET_MASK1, configNET_MASK2, configNET_MASK3);
	    IP4_ADDR(&netif_gw, configGW_ADDR0, configGW_ADDR1, configGW_ADDR2, configGW_ADDR3);

	    tcpip_init(NULL, NULL);

	    netifapi_netif_add(&netif, &netif_ipaddr, &netif_netmask, &netif_gw, &enet_config, EXAMPLE_NETIF_INIT_FN,
	                       tcpip_input);
	    netifapi_netif_set_default(&netif);
	    netifapi_netif_set_up(&netif);

	    PRINTF("\r\n************************************************\r\n");
	    PRINTF(" TCP Echo example\r\n");
	    PRINTF("************************************************\r\n");
	    PRINTF(" IPv4 Address     : %u.%u.%u.%u\r\n", ((u8_t *)&netif_ipaddr)[0], ((u8_t *)&netif_ipaddr)[1],
	           ((u8_t *)&netif_ipaddr)[2], ((u8_t *)&netif_ipaddr)[3]);
	    PRINTF(" IPv4 Subnet mask : %u.%u.%u.%u\r\n", ((u8_t *)&netif_netmask)[0], ((u8_t *)&netif_netmask)[1],
	           ((u8_t *)&netif_netmask)[2], ((u8_t *)&netif_netmask)[3]);
	    PRINTF(" IPv4 Gateway     : %u.%u.%u.%u\r\n", ((u8_t *)&netif_gw)[0], ((u8_t *)&netif_gw)[1],
	           ((u8_t *)&netif_gw)[2], ((u8_t *)&netif_gw)[3]);
	    PRINTF("************************************************\r\n");

}

/*Encryption*/
static size_t encrypt_msg(uint8_t *test_string, uint8_t padded_msg[]){/*Function to encrypt*/

	struct AES_ctx ctx;
	size_t test_string_len, padded_len;

	/* CRC data */
	CRC_Type *base = CRC0;
	uint32_t checksum32;

	//PRINTF("AES and CRC test task\r\n");

	//PRINTF("\nTesting AES128\r\n\n");
	/* Init the AES context structure */
	AES_init_ctx_iv(&ctx, key, iv);

	/* To encrypt an array its lenght must be a multiple of 16 so we add zeros */
	test_string_len = strlen(test_string);
	padded_len = test_string_len + (16 - (test_string_len%16) );
	memcpy(padded_msg, test_string, test_string_len);

	AES_CBC_encrypt_buffer(&ctx, padded_msg,padded_len);

	//PRINTF("Encrypted Message: ");
	/*for(int i=0; i<padded_len; i++) {
		PRINTF("0x%02x,", padded_msg[i]);
	}*/
	//PRINTF("%s", padded_msg);
	//PRINTF("\r\n");

	return test_string_len;


}
static void decrypt_msg(uint8_t encrypted_msg[], size_t encrypted_msg_size){/*Function to decrypt*/

	struct AES_ctx ctx;
	//uint8_t decrypted_msg[512] = {0};
	size_t decrypted_size;
	decrypted_size = encrypted_msg_size + (16 - (encrypted_msg_size%16) );
	memcpy(decrypted_msg, encrypted_msg, decrypted_size);

	//PRINTF("Pre-decrypted Message: \n");
	//PRINTF("%s", decrypted_msg);
	//PRINTF("Decrypted Message: \n");
	/* Init the AES context structure */
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, decrypted_msg, decrypted_size);

	//PRINTF("%s", decrypted_msg);
	//PRINTF("\r\n");
}

/*TCP/IP*/
int server_create(void *arg){

	LWIP_UNUSED_ARG(arg);

  /* Create a new connection identifier. */
/* Bind connection to well known port number 7. */
#if LWIP_IPV6
	conn = netconn_new(NETCONN_TCP_IPV6);
	netconn_bind(conn, IP6_ADDR_ANY, PORT);
#else /* LWIP_IPV6 */
	conn = netconn_new(NETCONN_TCP); //socket
	netconn_bind(conn, IP_ADDR_ANY, PORT); //bign()
#endif /* LWIP_IPV6 */
LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return);

	if(conn!=NULL)
		return 1;
	else
		return 0;

}
err_t server_accept(){/*Creación de servidor*/
	err_t  err_1;
	netconn_listen(conn);
	err_1 = netconn_accept(conn, &newconn);
	return err_1;

}
void close(void){
	netconn_close(newconn);
	netconn_delete(newconn);
}
/*send/receive*/
void send_msg(uint8_t *test_string){
	err_t err;

	PRINTF("En función de mensaje :%s \n",test_string);

	uint8_t padded_msg[512] = {0};
	encrypt_msg(test_string,padded_msg);
	uint8_t len = strlen(padded_msg);
	//CRC
	//

	err = netconn_write(newconn, padded_msg, len, NETCONN_COPY);//send()
	if (err != ERR_OK) {
		printf("tcpecho: netconn_write: error \"%s\"\n", lwip_strerr(err));
	}
}
void receive_msg(void){
	err_t err;
	struct netbuf *buf;
	uint8_t *data;
	u16_t len, len_to_send;
	uint8_t padded_msg[512] = {0};
	uint8_t bodymsg[512] = {0};
	uint32_t checksum32;
    stCRC mycrc;

		while ((err = netconn_recv(newconn, &buf)) == ERR_OK && !SWpress2) {//recv()

			do {

				netbuf_data(buf, &data, &len); /*Recivo de información*/
				size_t len_msgbody = messageBody(data,bodymsg);/*obtención del mensaje sólo, quitando los 4 bytes del CRC*/
				len_msgbody = (len_msgbody/2) - 4;
				get_CRC(data);	/*obtención del CRC, ultimos 4 bytes */


				decrypt_msg(bodymsg,len_msgbody);/*Decripción del cuerpo del mensaje, sin CRC*/
  				PRINTF("DATA: %s \n", decrypted_msg);
				PRINTF("INFO: sending data %s \n", decrypted_msg);

				len_to_send = encrypt_msg(decrypted_msg, padded_msg);/*Re-encriptación del cuerpo del mensaje*/
				PRINTF("INFO: Encrypted message: %s", padded_msg);

				checksum32 = calculate_CRC(padded_msg,len_msgbody);/*calculo de CRC re-encriptado*/
				mycrc.crc32 = checksum32;

				PRINTF("CRC-32: 0x%08x\r\n", mycrc.crc32);

				len_to_send = len_to_send + concatenate_strToSend_CRC(mycrc,padded_msg);/*Concateneo de mensaje re-encriptado + CRC*/
				err = netconn_write(newconn, toSend, len_to_send, NETCONN_COPY);//envio de mensaje re-encriptado + CRC


#if 0
	if (err != ERR_OK) {
	printf("tcpecho: netconn_write: error \"%s\"\n", lwip_strerr(err));
	}
#endif
			} while (netbuf_next(buf) >= 0);
			netbuf_delete(buf);
			}
		close();

}

size_t messageBody(uint8_t *data,uint8_t bodymsg[]){
	size_t test_string_len,padded_len;
	test_string_len = strlen(data);
	memcpy(bodymsg, data, test_string_len-8);

	return test_string_len;

}
static void get_CRC(uint8_t *data){

	uint8_t CRC[8];
	size_t fin, ini;
	fin = strlen(data) - 2;
	ini = fin -8 ;
	substr(data,CRC,ini,fin);
	PRINTF("%s\n",CRC);

}
static void substr(uint8_t *cad,uint8_t *sub,size_t ini,size_t fin){

	int ic,is = 0;
	for(ic = ini;ic<=fin;ic++){
		sub[is] = cad[ic];
		is++;
	}

}
static uint32_t calculate_CRC(uint8_t padded_msg[],size_t padded_len){

	/* CRC data */
	CRC_Type *base = CRC0;
	uint32_t checksum32;
	//PRINTF("\nTesting CRC32\r\n\n");

	InitCrc32(base, 0xFFFFFFFFU);
	CRC_WriteData(base, (uint8_t *)&padded_msg[0], padded_len);
	checksum32 = CRC_Get32bitResult(base);
	//PRINTF("CRC-32: 0x%08x\r\n", checksum32);

	return checksum32;

}

static void InitCrc32(CRC_Type *base, uint32_t seed)
{
    crc_config_t config;

    config.polynomial         = 0x04C11DB7U;
    config.seed               = seed;
    config.reflectIn          = true;
    config.reflectOut         = true;
    config.complementChecksum = true;
    config.crcBits            = kCrcBits32;
    config.crcResult          = kCrcFinalChecksum;

    CRC_Init(base, &config);
}
static u16_t concatenate_strToSend_CRC(stCRC CRC,uint8_t* msg){
	size_t len_msg = strlen(msg);

	for (int x = 0;x<4;x++){
		msg[len_msg] = CRC.strcrc[x];
		len_msg++;
	}
	len_msg = strlen(msg);
	toSend = (int*)malloc(len_msg*sizeof(int));
	strncpy(toSend,msg, len_msg);

	return len_msg;

}
