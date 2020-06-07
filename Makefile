PROGRAM = main

FLASH_SIZE ?= 8

EXTRA_CFLAGS += -I../.. -DESP_OPEN_RTOS

include $(SDK_PATH)/common.mk

monitor:
	$(FILTEROUTPUT) --port $(ESPPORT) --baud $(ESPBAUD) --elf $(PROGRAM_OUT)
