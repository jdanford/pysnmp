#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
from typing import Any, Callable, List, Optional

from pyasn1.compat.octets import null
from pyasn1.type.base import Asn1Type

from pysnmp import debug
from pysnmp.entity.engine import SnmpEngine
from pysnmp.proto.api import v1, v2c  # backend is always SMIv2 compliant
from pysnmp.proto.proxy import rfc2576
from pysnmp.proto.rfc1902 import ObjectName

VarBind = tuple[ObjectName, Asn1Type]
NotificationReceiverCallback = Callable[
    [
        SnmpEngine,  # snmpEngine
        int,  # messageProcessingModel
        Any,  # securityModel
        Any,  # securityName
        Any,  # securityLevel
        Any,  # contextEngineId
        Any,  # contextName
        Any,  # pduVersion
        v2c.SNMPv2TrapPDU,  # PDU
        Optional[v1.TrapPDU],  # origPDU
        int,  # maxSizeResponseScopedPDU
        int,  # stateReference
        List[VarBind],  # varBinds
        Any,  # self.__cbCtx
    ],
    None,
]


# 3.4
class NotificationReceiver:
    pduTypes = (
        v1.TrapPDU.tagSet,
        v2c.SNMPv2TrapPDU.tagSet,
        v2c.InformRequestPDU.tagSet,
    )

    def __init__(
        self,
        snmpEngine: SnmpEngine,
        cbFun: NotificationReceiverCallback,
        cbCtx: Any = None,
    ):
        snmpEngine.msgAndPduDsp.registerContextEngineId(
            null, self.pduTypes, self.processPdu  # '' is a wildcard
        )

        self.__snmpTrapCommunity = ""
        self.__cbFun = cbFun
        self.__cbCtx = cbCtx

        def storeSnmpTrapCommunity(
            snmpEngine: SnmpEngine, execpoint: Any, variables: Any, cbCtx: Any
        ):
            self.__snmpTrapCommunity = variables.get("communityName", "")

        snmpEngine.observer.registerObserver(
            storeSnmpTrapCommunity, "rfc2576.processIncomingMsg"
        )

    def close(self, snmpEngine: SnmpEngine):
        snmpEngine.msgAndPduDsp.unregisterContextEngineId(null, self.pduTypes)
        self.__cbFun = self.__cbCtx = None

    def processPdu(
        self,
        snmpEngine,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
        contextName,
        pduVersion,
        PDU,
        maxSizeResponseScopedPDU,
        stateReference,
    ):
        # Agent-side API complies with SMIv2
        if messageProcessingModel == 0:
            origPdu = PDU
            PDU = rfc2576.v1ToV2(PDU, snmpTrapCommunity=self.__snmpTrapCommunity)
        else:
            origPdu = None

        varBinds = v2c.apiPDU.getVarBinds(PDU)

        debug.logger & debug.flagApp and debug.logger(
            "processPdu: stateReference {}, user cbFun {}, cbCtx {}, varBinds {}".format(
                stateReference, self.__cbFun, self.__cbCtx, varBinds
            )
        )

        assert self.__cbFun is not None
        self.__cbFun(
            snmpEngine,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            PDU,
            origPdu,
            maxSizeResponseScopedPDU,
            stateReference,
            varBinds,
            self.__cbCtx,
        )
