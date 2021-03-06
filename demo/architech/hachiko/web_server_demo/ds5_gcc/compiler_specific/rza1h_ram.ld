/*******************************************************************************
* DISCLAIMER
* This software is supplied by Renesas Electronics Corporation and is only
* intended for use with Renesas products. No other uses are authorized. This
* software is owned by Renesas Electronics Corporation and is protected under
* all applicable laws, including copyright laws.
* THIS SOFTWARE IS PROVIDED "AS IS" AND RENESAS MAKES NO WARRANTIES REGARDING
* THIS SOFTWARE, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING BUT NOT
* LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
* AND NON-INFRINGEMENT. ALL SUCH WARRANTIES ARE EXPRESSLY DISCLAIMED.
* TO THE MAXIMUM EXTENT PERMITTED NOT PROHIBITED BY LAW, NEITHER RENESAS
* ELECTRONICS CORPORATION NOR ANY OF ITS AFFILIATED COMPANIES SHALL BE LIABLE
* FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES FOR
* ANY REASON RELATED TO THIS SOFTWARE, EVEN IF RENESAS OR ITS AFFILIATES HAVE
* BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
* Renesas reserves the right, without notice, to make changes to this software
* and to discontinue the availability of this software. By using this software,
* you agree to the additional terms and conditions found by accessing the
* following link:
* http://www.renesas.com/disclaimer
*
* Copyright (C) 2014 Renesas Electronics Corporation. All rights reserved.
*******************************************************************************/
/******************************************************************************
* File Name     : GNU_e2studio-IRAM.ld
* Device(s)     : RZ/A1H (R7S721001)
* Tool-Chain    : GNUARM-NONEv14.02-EABI
* H/W Platform  : RSK+RZA1H CPU Board
* Description   : Linker file for projects that require to run from 
*               : Internal device RAM 
******************************************************************************/
/******************************************************************************
* History       : DD.MM.YYYY Version Description
*               : 21.10.2014 1.00
******************************************************************************/
OUTPUT_FORMAT("elf32-littlearm", "elf32-bigarm", "elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(start)

/* Base Address RAM Memory Table 10-Mbyte on-chip RAM */  
/* Total RAM available 10112K */
MEMORY 
{
	/* Internal RAM address range H'2000_0000 to H'2001_FFFF is configured as data retention RAM */
	/* Write access to this address range has to be enabled by writing to registers SYSCR1 and SYSCR2 */
	RAM0L (rwx)   : ORIGIN = 0x20040000, LENGTH = 0x000C0000  /* Page 0 Lower bank ( 896KB) H'20020000 to H'200FFFFF */
	RAM1L (rwx)   : ORIGIN = 0x20100000, LENGTH = 0x00100000  /* Page 1 Upper bank (1024KB) H'20100000 to H'201FFFFF */
	RAM2L (rwx)   : ORIGIN = 0x20200000, LENGTH = 0x00100000  /* Page 2 Upper bank (1024KB) H'20200000 to H'202FFFFF */
	RAM3L (rwx)   : ORIGIN = 0x20300000, LENGTH = 0x00100000  /* Page 3 Upper bank (1024KB) H'20300000 to H'203FFFFF */
	RAM4L (rwx)   : ORIGIN = 0x20400000, LENGTH = 0x00100000  /* Page 4 Upper bank (1024KB) H'20400000 to H'204FFFFF */
	RAM0U (rwx)   : ORIGIN = 0x20500000, LENGTH = 0x00100000  /* Page 0 Upper bank (1024KB) H'20500000 to H'205FFFFF */
	RAM1U (rwx)   : ORIGIN = 0x20600000, LENGTH = 0x00100000  /* Page 1 Upper bank (1024KB) H'20600000 to H'206FFFFF */
	RAM2U (rwx)   : ORIGIN = 0x20700000, LENGTH = 0x00100000  /* Page 2 Upper bank (1024KB) H'20700000 to H'207FFFFF */
	RAM3U (rwx)   : ORIGIN = 0x20800000, LENGTH = 0x00100000  /* Page 3 Upper bank (1024KB) H'20800000 to H'208FFFFF */
	RAM4U (rwx)   : ORIGIN = 0x20900000, LENGTH = 0x00100000  /* Page 4 Upper bank (1024KB) H'20900000 to H'209FFFFF */
	SDRAM (rwx)   : ORIGIN = 0x48000000, LENGTH = 0x02000000  /* SDRAM 32MB attached to CS2 H'08000000 to H'09FFFFFF */

	RAM01234L (rwx) : ORIGIN = 0x20040000, LENGTH = 0x007C0000

	RAM_NO_CACHE (rwx) : ORIGIN = 0x60700000, LENGTH = 0x00100000 /* Page 3U Mirror */

	ROM       (rw)  : ORIGIN = 0x18000000, LENGTH = 0x02000000  /* SPI ROM attached to H'18000000 to H'19FFFFFF */
	VRAM1     (rw)  : ORIGIN = 0x60600000, LENGTH = 0x00100000
	VRAM2     (rw)  : ORIGIN = 0x60900000, LENGTH = 0x00100000 
}

PROGRAM_STACK_SIZE    = 0x8000; 	/* Application stack                  */
IRQ_STACK_SIZE	      = 0x2000;     /* IRQ mode stack                     */
FIQ_STACK_SIZE	      = 0x2000;     /* FRQ mode stack                     */
SVC_STACK_SIZE	      = 0x2000;     /* SVC mode stack                     */
ABT_STACK_SIZE	      = 0x2000;     /* ABT mode stack                     */
TTB_SIZE              = 0x8000;     /* Level-1 Translation Table for MMU  */

EXEC_BASE             = 0x20040000; /* VECTOR_TABLE located here          */

SECTIONS
{
	.reset EXEC_BASE :
	{
		execute = .;
		*start.o (.text)
		.	= ALIGN(0x4);
		*(.text.startup)
		address_end_reset = .;
	} > RAM01234L

	.text :
	{
		text_start = .;
		*(.text)
		address_end_text = .;
	} > RAM01234L
	
	.rodata :
	{
		*(.rodata)
		*(.rodata.*)
		. = ALIGN(0x8);
		address_start_data_ROM = .;
		*(.data)
		*(.data.*)
		*(.got.plt)
		*(.got)
		. = ALIGN(0x8);
		address_end_data_ROM = .;
		PROVIDE(end = .);
	} > RAM01234L

	.data address_end_data_ROM :
	{
		address_start_data_RAM = .;
		. += (address_end_data_ROM - address_start_data_ROM);
		address_end_data_RAM = .;
    } > RAM01234L

	.bss :
	{
         _bss = .;
         PROVIDE(__bss_start__ = .);
         *(.bss)
         *(.bss.**)
         *(COMMON)
		 . = ALIGN(0x4);
         PROVIDE(__bss_end__ = .);
         _ebss = .;
         _end = .;
    } >RAM01234L

	.irq_stack : ALIGN(0x4000)
	{
		irq_stack_start = .;
		.  += IRQ_STACK_SIZE;
		.	= ALIGN(0x4);
		irq_stack_end = .;
	} >RAM01234L

	.fiq_stack :
	{
		fiq_stack_start = .;
		.  += FIQ_STACK_SIZE;
		.	= ALIGN(0x4);
		fiq_stack_end = .;
	} >RAM01234L

	.svc_stack :
	{
		PROVIDE(svc_stack_start = .);
		.  += SVC_STACK_SIZE;
		.	= ALIGN(0x4);
		svc_stack_end = .;
	} >RAM01234L

	.abt_stack :
	{
		abt_stack_start = .;
		.  += ABT_STACK_SIZE;
		.	= ALIGN(0x4);
		abt_stack_end = .;
	} >RAM01234L

	.program_stack :
	{
		program_stack_start = .;
		.  += PROGRAM_STACK_SIZE;
		.	= ALIGN(0x4);
		program_stack_end = .;
	} >RAM01234L

	/* L1 translation table must be aligned to 16KB Boundary!           */
	/* Please refer to Cortex-A Series Version: 4.0 Programmerís Guide, */
	/* section 9.4 First level address translation                      */
	.ttb_mmu1 : ALIGN(0x4000)
	{
		ttb_mmu1_base = .;
		.  += TTB_SIZE;
		.	= ALIGN(0x4);
		ttb_mmu1_end = .;
	} >RAM01234L

	.BSS_DMAC_SAMPLE_INTERNAL_RAM (NOLOAD) :
    {
        *(.BSS_DMAC_SAMPLE_INTERNAL_RAM)
    } >RAM_NO_CACHE

	/* NOLOAD directs linker NOT to fill VRAMx_SECTION with 0.          */
	/* Usage of NOLOAD increases speed of linker and download to target */
	.VRAM1 (NOLOAD) : {} > VRAM1
	.VRAM2 (NOLOAD) : {} > VRAM2
}