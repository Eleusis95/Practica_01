#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "fsl_port.h"
#include "fsl_gpio.h"
#include "fsl_common.h"

#include "pin_mux.h"
#include "clock_config.h"

/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "event_groups.h"

#include "Encryption_and_Integrity_Layer.h"

volatile bool SWpress2=false; //Variable bool para guardar el estado logico si se presiono el SW2
volatile bool SWpress3=false;//Variable bool para guardar el estado logico si se presiono el SW3
/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Interrupt service function of switch SW3.
 *
 */
void BOARD_SW3_IRQ_HANDLER(void)
{

#if (defined(FSL_FEATURE_PORT_HAS_NO_INTERRUPT) && FSL_FEATURE_PORT_HAS_NO_INTERRUPT)
    /* Clear external interrupt flag. */
    GPIO_GpioClearInterruptFlags(BOARD_SW_GPIO, 1U << BOARD_SW_GPIO_PIN);
#else
    /* Clear external interrupt flag. */
    GPIO_PortClearInterruptFlags(BOARD_SW3_GPIO, 1U << BOARD_SW3_GPIO_PIN);
#endif
    /* Change state of button. */
    SWpress3 = true;
}

/*!
 * @brief Interrupt service function of switch SW2.
 *
 */
void BOARD_SW2_IRQ_HANDLER(void)
{

#if (defined(FSL_FEATURE_PORT_HAS_NO_INTERRUPT) && FSL_FEATURE_PORT_HAS_NO_INTERRUPT)
    /* Clear external interrupt flag. */
    GPIO_GpioClearInterruptFlags(BOARD_SW_GPIO, 1U << BOARD_SW_GPIO_PIN);
#else
    /* Clear external interrupt flag. */
    GPIO_PortClearInterruptFlags(BOARD_SW2_GPIO, 1U << BOARD_SW2_GPIO_PIN);
#endif
    /* Change state of button. */
    SWpress2 = true;
}

void BOARD_InitGPIOInterrupts (void)
{
	int result = 0;

    /* Define the init structure for the input switch pin */
    gpio_pin_config_t sw_config = {
        kGPIO_DigitalInput,
        0,
    };

    /* Define the init structure for the output LED pin */
    gpio_pin_config_t led_config = {
        kGPIO_DigitalOutput,
        0,
    };

    PORT_SetPinInterruptConfig(BOARD_SW3_PORT, BOARD_SW3_GPIO_PIN, kPORT_InterruptFallingEdge);
	PORT_SetPinInterruptConfig(BOARD_SW2_PORT, BOARD_SW2_GPIO_PIN, kPORT_InterruptFallingEdge);

	EnableIRQ(BOARD_SW3_IRQ);
	EnableIRQ(BOARD_SW2_IRQ);

	GPIO_PinInit(BOARD_SW3_GPIO, BOARD_SW3_GPIO_PIN, &sw_config);
	GPIO_PinInit(BOARD_SW2_GPIO, BOARD_SW2_GPIO_PIN, &sw_config);


    //Set PORTA (PORTA_IRQn) Interrupt level to 3 (higher than SYSCALL),
	//configMAX_SYSCALL_INTERRUPT_PRIORITY priority is 2.
	//NVIC_SetPriority();
	//Set PORTA Interrupt level to 3 (higher than SYSCALL), configMAX_SYSCALL_INTERRUPT_PRIORITY priority is 2.
	result = NVIC_GetPriority(PORTA_IRQn);
	NVIC_SetPriority(PORTA_IRQn,3); //PORTA vector is 59
	result = NVIC_GetPriority(PORTA_IRQn);

    //Set PORTC (PORTC_IRQn) Interrupt level to 3 (higher than SYSCALL),
	//configMAX_SYSCALL_INTERRUPT_PRIORITY priority is 2.
    //NVIC_SetPriority();
	//Set PORTC Interrupt level to 3, configMAX_SYSCALL_INTERRUPT_PRIORITY priority is 2.
	result = NVIC_GetPriority(PORTC_IRQn);
	NVIC_SetPriority(PORTC_IRQn,3); //PORTC vector is 61
	result = NVIC_GetPriority(PORTC_IRQn);

	 GPIO_PinInit(BOARD_LED_RED_GPIO, BOARD_LED_RED_GPIO_PIN, &led_config);
	 GPIO_PinInit(BOARD_LED_BLUE_GPIO, BOARD_LED_BLUE_GPIO_PIN, &led_config);
	 GPIO_PinInit(BOARD_LED_GREEN_GPIO, BOARD_LED_GREEN_GPIO_PIN, &led_config);


   //Test code for proving that the gpio interrupts are happening with NO FreeRTOS
//	while (1)
//	{
//		if (g_ButtonPress)
//		{
//			PRINTF(" Push Button was press \r\n");
//
//			/* Reset state of button. */
//			g_ButtonPress = false;
//		}
//	}
}
