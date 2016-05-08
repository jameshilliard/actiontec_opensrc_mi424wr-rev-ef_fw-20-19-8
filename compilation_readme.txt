Distributions (DIST):
=====================
    MC524WR
    MI424WR

Target Customers (ACTION_TEC_CUSTOMER):
======================================
    ACTION_TEC_VERIZON=y
    ACTION_TEC_NCS=y

Hardware Revs:
==============
    CONFIG_MC524WR_REV=0x2A
    CONFIG_MC524WR_REV=0x5A
    CONFIG_MC524WR_REV=0x6A
    CONFIG_MC524WR_REV=0x7A
    CONFIG_MC524WR_REV=0x8A

Big vs Small Image:
===================
    Big Image: Nothing to be specified on command line
    Small Image: ACTION_TEC_SMALL_IMG=y

License File:
=============
    LIC=../jpkg_actiontec_oct.lic


OpenRG  for Actiontec MC524WR (Full Feature Image/Active Image/Big Image)
=========================================================================
make DIST=<distribution> <ACTION_TEC_CUSTOMER=y> CONFIG_MC524WR_REV=<rev> LIC=../<license filename> && make


OpenRG  for Actiontec MC524WR (Small Image/Backup Image)
=========================================================
make DIST=<distribution> <ACTION_TEC_CUSTOMER=y> CONFIG_MC524WR_REV=<rev> ACTION_TEC_SMALL_IMG=y LIC=../<license filename> && make



OpenRG  for Actiontec MC524WR Compilation (Small/Big Image)
-----------------------------------------------------------
To build the BIG IMAGE openrg.img for 0x6A WITH NAS AND PRINTER FEATURES run:
$ make config DIST=MC524WR ACTION_TEC_VERIZON=y ACTION_TEC_NAS_FEATURES=y CONFIG_MC524WR_REV=0x6A CONFIG_RG_WPS_ALL_MODES=y LIC=../jpkg_actiontec_oct.lic && make

***** To build the BIG IMAGE openrg.img for 0x6A WITH IGMP FEATURES run (MAIN BUILD SINCE 20.7.1): ******
$ make config DIST=MC524WR ACTION_TEC_VERIZON=y ACTION_TEC_IGMP_ENABLED=y CONFIG_MC524WR_REV=0x6A CONFIG_RG_WPS_ALL_MODES=y LIC=../jpkg_actiontec_oct.lic && make

To build the BIG IMAGE openrg.img for 0x6A WITH BOTH IGMP AND NAS FEATURES (File Server and Printer Server Support) run:
$ make config DIST=MC524WR ACTION_TEC_VERIZON=y ACTION_TEC_IGMP_ENABLED=y ACTION_TEC_NAS_FEATURES=y CONFIG_MC524WR_REV=0x6A CONFIG_RG_WPS_ALL_MODES=y LIC=../jpkg_actiontec_oct.lic && make

To build the BIG IMAGE openrg.img for 0x6A WITH File Server Support run:
$ make config DIST=MC524WR ACTION_TEC_VERIZON=y ACTION_TEC_IGMP_ENABLED=y ACTION_TEC_FILE_SERVER_ONLY_FEATURES=y CONFIG_MC524WR_REV=0x6A CONFIG_RG_WPS_ALL_MODES=y LIC=../jpkg_actiontec_oct.lic && make

****** OpenRG for Actiontec MC524WR Compilation with 802.11N supported
------------------------------------------------------------------------------
******** With 802.11G ***************
make config DIST=MC524WR ACTION_TEC_VERIZON=y CONFIG_MC524WR_REV=0x6A CONFIG_RG_WPS_ALL_MODES=y LIC=../jpkg_actiontec_oct.lic && make

******** With 802.11N ***************
make config DIST=MC524WR ACTION_TEC_VERIZON=y ACTION_TEC_80211N=y CONFIG_RG_ATHEROS_HW_AR5416=y CONFIG_MC524WR_REV=0x6A CONFIG_RG_WPS_ALL_MODES=y LIC=../jpkg_actiontec_oct.lic && make

To build the SMALL IMAGE openrg.img for 0x6A run:
$ make config DIST=MC524WR ACTION_TEC_SMALL_IMG=y ACTION_TEC_VERIZON=y CONFIG_MC524WR_REV=0x6A CONFIG_RG_WPS_ALL_MODES=y LIC=../jpkg_actiontec_oct.lic && make


To build the Big openrg.img for 0x2A run:
$ make config DIST=MC524WR ACTION_TEC_VERIZON=y CONFIG_MC524WR_REV=0x2A LIC=../jpkg_actiontec_oct.lic && make
To build the Small openrg.img for 0x2A run:
$ make config DIST=MC524WR ACTION_TEC_SMALL_IMG=y ACTION_TEC_VERIZON=y CONFIG_MC524WR_REV=0x2A LIC=../jpkg_actiontec_oct.lic && make

========================================================================

OpenRG  for Actiontec MC524WR Compilation
--------------------------------------------------
To build the openrg.img for 0x5A run:
$ make config DIST=MC524WR ACTION_TEC_VERIZON=y CONFIG_MC524WR_REV=0x5A LIC=../jpkg_actiontec_oct.lic && make

To build the openrg.img for 0x2A run:
$ make config DIST=MC524WR ACTION_TEC_VERIZON=y CONFIG_MC524WR_REV=0x2A LIC=../jpkg_actiontec_oct.lic && make

========================================================================

OpenRG  for Actiontec MI424WR Compilation
--------------------------------------------------
To build the openrg.img run:
$ make config DIST=MI424WR ACTION_TEC_VERIZON=y LIC=../jpkg_actiontec_oct.lic && make

RGLoader  for Actiontec MI424WR Compilation
--------------------------------------------------
To build the rgloader.img run:
$ cd /home/alex/igor/rg-4.7.5.3.14/rg
$ make config DIST=RGLOADER_MI424WR LIC=../jpkg_actiontec_oct.lic && make

========================================================================
