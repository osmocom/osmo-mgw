osmo-mgw - Osmocom MGW (Media GateWay) Implementation
=====================================================

This repository contains a C-language implementation of an MGW (Media
GateWay) for use [not only] within the 2G (GSM) and/or 3G (UMTS)
Cellular Network built using Osmocom CNI (Cellular Network
Infrastructure) software.

The OsmoMGW program provides an MGCP interface towards an MGCP call agent
(client) like OsmoMSC and OsmoBSC, and receives and sends RTP streams as
configured via the MGCP control plane.

This Media Gateway implementation is capable of

* streaming RTP for 2G (3GPP AoIP and Abis-over-IP)
* streaming RTP for 3G (IuCS including the IuFP protocol)
* TDM (E1/T1) based Abis interface with TRAU frames on 16k sub-slots
* basic support for LCLS (Local Call, Local Switch) related features
* various built-in translation capabilities
  * between Abis TRAU frames and RTP formats
  * between 2G AMR/RTP and 3G AMR/IuFP/RTP
  * between bandwidth-efficient and octet-aligned AMR
  * between different standards for encapsulating GSM HR codec frames in RTP

osmo-mgw is typically co-located with

 * osmo-bsc (GSM BSC)
 * osmo-msc (GSM/UMTS MSC)
 * osmo-hnbgw (UMTS HNBGW); osmo-mgw implements RTP relay between Iuh
   and IuCS interfaces

The libosmo-mgcp-client library exposes utilities used by e.g. OsmoMSC
(found in osmo-msc.git) to instruct OsmoMGW via its MGCP service.

Homepage
--------

You can find the OsmoMGW issue tracker and wiki online at
<https://osmocom.org/projects/osmo-mgw> and <https://osmocom.org/projects/osmo-mgw/wiki>.


GIT Repository
--------------

You can clone from the official osmo-mgw.git repository using

        git clone https://gitea.osmocom.org/cellular-infrastructure/osmo-mgw

There is a web interface at <https://gitea.osmocom.org/cellular-infrastructure/osmo-mgw>


Documentation
-------------

User Manuals and VTY reference manuals are [optionally] built in PDF form
as part of the build process.

Pre-rendered PDF version of the current "master" can be found at
[User Manual](https://ftp.osmocom.org/docs/latest/osmomgw-usermanual.pdf)
as well as the [VTY Reference Manual](https://ftp.osmocom.org/docs/latest/osmomgw-vty-reference.pdf)


Mailing List
------------

Discussions related to osmo-mgw are happening on the
openbsc@lists.osmocom.org mailing list, please see
<https://lists.osmocom.org/mailman/listinfo/openbsc> for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.


Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We use a gerrit based patch submission/review process for managing
contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for
more details

The current patch queue for osmo-mgw can be seen at
<https://gerrit.osmocom.org/#/q/project:osmo-mgw+status:open>


History
-------

OsmoMGW originated from the OpenBSC project, which started as a minimalistic
all-in-one implementation of the GSM Network. In 2017, OpenBSC had reached
maturity and diversity (including M3UA SIGTRAN and 3G support in the form of
IuCS and IuPS interfaces) that naturally lead to a separation of the all-in-one
approach to fully independent separate programs as in typical GSM networks.

OsmoMGW was one of the parts split off from the old openbsc.git. It originated
as a solution to merely navigate RTP streams through a NAT, but has since
matured.
