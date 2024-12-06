class RegisterRange:
    """
    Class representing a register or a range of registers.
    """

    def __init__(self, name, description, addr_low, addr_high=None):
        """
        Initialize the RegisterRange object.

        :param name: The name of the register or range.
        :param description: A brief description of the register or range.
        :param addr_low: The lower bound of the address range (inclusive).
        :param addr_high: The upper bound of the address range (inclusive, optional).
                          Defaults to the same value as addr_low.
        """
        self.name = name
        self.description = description
        self.addr_low = addr_low
        self.addr_high = addr_high if addr_high is not None else addr_low

    def __eq__(self, other):
        """
        Checks if the compared value is equal to or in the range [addr_low, addr_high].

        :param other: The value to compare (typically an integer).
        :return: True if the value is within the range, otherwise False.
        """
        if isinstance(other, int):
            return self.addr_low <= other <= self.addr_high
        return False

    def __str__(self):
        """
        String representation of the register range.

        :return: A human-readable string.
        """
        if self.addr_low == self.addr_high:
            return f"{self.name} (0x{self.addr_low:04X}): {self.description}"
        else:
            return f"{self.name} (0x{self.addr_low:04X}-0x{self.addr_high:04X}): {self.description}"


class MemoryMapLookup:
    """
    Lookup table for MMS and ADDR mappings from the
    OPEN Alliance 10BASE-T1x MAC-PHY Serial Interface
    and 10BASE-T1S MAC-PHY Ethernet Controller with SPI
    LAN8650/1
    """
    MMS0 = [
    RegisterRange("IDVER", "IDVersion", 0x0000),
    RegisterRange("PHYID", "PHYID", 0x0001),
    RegisterRange("STDCAP", "StandardCaps", 0x0002),
    RegisterRange("RESET", "ResetCtrlStatus", 0x0003),
    RegisterRange("CONFIG0", "Cfg0", 0x0004),
    RegisterRange("CONFIG1", "Cfg1", 0x0005),
    RegisterRange("CONFIG2", "Cfg2", 0x0006),
    RegisterRange("RSVD", "Reserved", 0x0007),
    RegisterRange("STATUS0", "Status0", 0x0008),
    RegisterRange("STATUS1", "Status1", 0x0009),
    RegisterRange("RSVD", "Reserved", 0x000A),
    RegisterRange("BUFSTS", "BufferStatus", 0x000B),
    RegisterRange("IMSK0", "InterruptMask0", 0x000C),
    RegisterRange("IMSK1", "InterruptMask1", 0x000D),
    RegisterRange("RSVD", "Reserved", 0x000E, 0x000F),
    RegisterRange("TTSCAH", "TxTimestampCaptureAHigh", 0x0010),
    RegisterRange("TTSCAL", "TxTimestampCaptureALow", 0x0011),
    RegisterRange("TTSCBH", "TxTimestampCaptureBHigh", 0x0012),
    RegisterRange("TTSCBL", "TxTimestampCaptureBLow", 0x0013),
    RegisterRange("TTSCCH", "TxTimestampCaptureCHigh", 0x0014),
    RegisterRange("TTSCCL", "TxTimestampCaptureCLow", 0x0015),
    RegisterRange("RSVD", "Reserved", 0x0016, 0x001F),
    RegisterRange("MDIOACC0", "MDIOAccess0", 0x0020),
    RegisterRange("MDIOACC1", "MDIOAccess1", 0x0021),
    RegisterRange("MDIOACC2", "MDIOAccess2", 0x0022),
    RegisterRange("MDIOACC3", "MDIOAccess3", 0x0023),
    RegisterRange("MDIOACC4", "MDIOAccess4", 0x0024),
    RegisterRange("MDIOACC5", "MDIOAccess5", 0x0025),
    RegisterRange("MDIOACC6", "MDIOAccess6", 0x0026),
    RegisterRange("MDIOACC7", "MDIOAccess7", 0x0027),
    RegisterRange("RSVD", "Reserved", 0x0028, 0xFEFF),
    RegisterRange("Clause 22", "PHYClause22Std", 0xFF00, 0xFF1F),
    RegisterRange("Clause 29", "PHYClause29Extended", 0xFF20, 0xFF3F),
    RegisterRange("RSVD", "Reserved", 0xFF40, 0xFFFF),
    ]

    # Defined by Microchip
    MMS1 = [
    RegisterRange("MAC_NCR", "MACNetCtrl", 0x00),
    RegisterRange("MAC_NCFGR", "MACNetCfg", 0x01),
    RegisterRange("RSVD", "Reserved", 0x05, 0x1F),
    RegisterRange("MAC_HRB", "MACHashRegBottom", 0x20),
    RegisterRange("MAC_HRT", "MACHashRegTop", 0x21),
    RegisterRange("MAC_SAB1", "MACSpecAddr1Bottom", 0x22),
    RegisterRange("MAC_SAT1", "MACSpecAddr1Top", 0x23),
    RegisterRange("MAC_SAB2", "MACSpecAddr2Bottom", 0x24),
    RegisterRange("MAC_SAT2", "MACSpecAddr2Top", 0x25),
    RegisterRange("MAC_SAB3", "MACSpecAddr3Bottom", 0x26),
    RegisterRange("MAC_SAT3", "MACSpecAddr3Top", 0x27),
    RegisterRange("MAC_SAB4", "MACSpecAddr4Bottom", 0x28),
    RegisterRange("MAC_SAT4", "MACSpecAddr4Top", 0x29),
    RegisterRange("MAC_TIDM1", "MACTypeIDMatch1", 0x2A),
    RegisterRange("MAC_TIDM2", "MACTypeIDMatch2", 0x2B),
    RegisterRange("MAC_TIDM3", "MACTypeIDMatch3", 0x2C),
    RegisterRange("MAC_TIDM4", "MACTypeIDMatch4", 0x2D),
    RegisterRange("RSVD", "Reserved", 0x31),
    RegisterRange("MAC_SAMB1", "MACSpecAddrMask1Bottom", 0x32),
    RegisterRange("MAC_SAMT1", "MACSpecAddrMask1Top", 0x33),
    RegisterRange("RSVD", "Reserved", 0x37, 0x6E),
    RegisterRange("MAC_TISUBN", "TSUTimerIncSubNano", 0x6F),
    RegisterRange("MAC_TSH", "TSUTimerSecHigh", 0x70),
    RegisterRange("MAC_TSL", "TSUTimerSecLow", 0x74),
    RegisterRange("MAC_TN", "TSUTimerNano", 0x75),
    RegisterRange("MAC_TA", "TSUTimerAdjust", 0x76),
    RegisterRange("MAC_TI", "TSUTimerInc", 0x77),
    RegisterRange("RSVD", "Reserved", 0x7B, 0x01FF),
    RegisterRange("BMGR_CTL", "MACBufMgrCtrl", 0x0200),
    RegisterRange("RSVD", "Reserved", 0x0204, 0x0207),
    RegisterRange("STATS0", "Stats0", 0x0208),
    RegisterRange("STATS1", "Stats1", 0x0209),
    RegisterRange("STATS2", "Stats2", 0x020A),
    RegisterRange("STATS3", "Stats3", 0x020B),
    RegisterRange("STATS4", "Stats4", 0x020C),
    RegisterRange("STATS5", "Stats5", 0x020D),
    RegisterRange("STATS6", "Stats6", 0x020E),
    RegisterRange("STATS7", "Stats7", 0x020F),
    RegisterRange("STATS8", "Stats8", 0x0210),
    RegisterRange("STATS9", "Stats9", 0x0211),
    RegisterRange("STATS10", "Stats10", 0x0212),
    RegisterRange("STATS11", "Stats11", 0x0213),
    RegisterRange("STATS12", "Stats12", 0x0214),
    ]


    MMS2 = [
    RegisterRange("RSVD", "Reserved", 0x0000, 0x08F2),
    RegisterRange("T1SPCSCTL", "10BaseT1SPcsCtrl", 0x08F3),
    RegisterRange("T1SPCSSTS", "10BaseT1SPcsStatus", 0x08F4),
    RegisterRange("T1SPCSDIAG1", "10BaseT1SPcsDiag1", 0x08F5),
    RegisterRange("T1SPCSDIAG2", "10BaseT1SPcsDiag2", 0x08F6),
    ]

    MMS3 = [
    RegisterRange("RSVD", "Reserved", 0x0000, 0x0011),
    RegisterRange("T1PMAPMDEXTA", "BaseT1PmaPmdExtAbility", 0x0012),
    RegisterRange("RSVD", "Reserved", 0x0014, 0x0833),
    RegisterRange("T1PMAPMDCTL", "BaseT1PmaPmdCtrl", 0x0834),
    RegisterRange("RSVD", "Reserved", 0x0836, 0x08F8),
    RegisterRange("T1SPMACTL", "10BaseT1SPmaCtrl", 0x08F9),
    RegisterRange("T1SPMASTS", "10BaseT1SPmaStatus", 0x08FA),
    RegisterRange("T1STSTCTL", "10BaseT1STestModeCtrl", 0x08FB),
    ]

    MMS4 = [
    RegisterRange("RSVD", "Reserved", 0x0000, 0x000F),
    RegisterRange("CTRL1", "Ctrl1", 0x0010),
    RegisterRange("RSVD", "Reserved", 0x0012, 0x0017),
    RegisterRange("STS1", "Status1", 0x0018),
    RegisterRange("STS2", "Status2", 0x0019),
    RegisterRange("STS3", "Status3", 0x001A),
    RegisterRange("IMSK1", "InterruptMask1", 0x001C),
    RegisterRange("IMSK2", "InterruptMask2", 0x001D),
    RegisterRange("RSVD", "Reserved", 0x001F),
    RegisterRange("CTRCTRL", "CtrCtrl", 0x0020),
    RegisterRange("RSVD", "Reserved", 0x0022, 0x0023),
    RegisterRange("TOCNTH", "TimeoutCntHigh", 0x0024),
    RegisterRange("TOCNTL", "TimeoutCntLow", 0x0025),
    RegisterRange("BCNCNTH", "BeaconCntHigh", 0x0026),
    RegisterRange("BCNCNTL", "BeaconCntLow", 0x0027),
    RegisterRange("RSVD", "Reserved", 0x0029, 0x002F),
    RegisterRange("MULTID0", "PLCAMultiID0", 0x0030),
    RegisterRange("MULTID1", "PLCAMultiID1", 0x0031),
    RegisterRange("MULTID2", "PLCAMultiID2", 0x0032),
    RegisterRange("MULTID3", "PLCAMultiID3", 0x0033),
    RegisterRange("RSVD", "Reserved", 0x0035),
    RegisterRange("PRSSTS", "PLCAReconcilSubStatus", 0x0036),
    RegisterRange("RSVD", "Reserved", 0x0038, 0x003C),
    RegisterRange("PRTMGMT2", "PortMgmt2", 0x003D),
    RegisterRange("IWDTOH", "InactivWDTimeoutHigh", 0x003E),
    RegisterRange("IWDTOL", "InactivWDTimeoutLow", 0x003F),
    RegisterRange("TXMCTL", "TxMatchCtrl", 0x0040),
    RegisterRange("TXMPATH", "TxMatchPattern", 0x0041),
    RegisterRange("TXMPATL", "TxMatchPatternLow", 0x0042),
    RegisterRange("TXMMSKH", "TxMatchMaskHigh", 0x0043),
    RegisterRange("TXMMSKL", "TxMatchMaskLow", 0x0044),
    RegisterRange("TXMLOC", "TxMatchLocation", 0x0045),
    RegisterRange("RSVD", "Reserved", 0x0047, 0x0048),
    RegisterRange("TXMDLY", "TxMatchDelay", 0x0049),
    RegisterRange("RSVD", "Reserved", 0x004B, 0x004F),
    RegisterRange("RXMCTL", "RxMatchCtrl", 0x0050),
    RegisterRange("RXMPATH", "RxMatchPath", 0x0051),
    RegisterRange("RXMPATL", "RxMatchPathLow", 0x0052),
    RegisterRange("RXMMSKH", "RxMatchMaskHigh", 0x0053),
    RegisterRange("RXMMSKL", "RxMatchMaskLow", 0x0054),
    RegisterRange("RXMLOC", "RxMatchLocation", 0x0055),
    RegisterRange("RSVD", "Reserved", 0x0057, 0x0058),
    RegisterRange("RXMDLY", "RxMatchPacketDelay", 0x0059),
    RegisterRange("RSVD", "Reserved", 0x005B, 0x005F),
    RegisterRange("CBSSPTHH", "CBSStopThresholdHigh", 0x0060),
    RegisterRange("CBSSPTHL", "CBSStopThresholdLow", 0x0061),
    RegisterRange("CBSSTTHH", "CBSStartThresholdHigh", 0x0062),
    RegisterRange("CBSSTTHL", "CBSStartThresholdLow", 0x0063),
    RegisterRange("CBSSLPCTL", "CBSSlopeCtrl", 0x0064),
    RegisterRange("CBSTPLMTH", "CBSTopLimitHigh", 0x0065),
    RegisterRange("CBSTPLMTL", "CBSTopLimitLow", 0x0066),
    RegisterRange("CBSBTLMTH", "CBSBottomLimitHigh", 0x0067),
    RegisterRange("CBSBTLMTL", "CBSBottomLimitLow", 0x0068),
    RegisterRange("CBSCRCTRH", "CBSCreditCtrHigh", 0x0069),
    RegisterRange("CBSCRCTRL", "CBSCreditCtrLow", 0x006A),
    RegisterRange("CBSCTRL", "CBSCtrl", 0x006B),
    RegisterRange("RSVD", "Reserved", 0x006D, 0x006F),
    RegisterRange("PLCASKPCTL", "PLCASkipCtrl", 0x0070),
    RegisterRange("PLCATOSKP", "PLCATxOpportunitySkip", 0x0071),
    RegisterRange("RSVD", "Reserved", 0x0073),
    RegisterRange("ACMACTL", "AppCtrlMAC", 0x0074),
    RegisterRange("RSVD", "Reserved", 0x0076, 0x007F),
    RegisterRange("SLPCTL0", "SleepCtrl0", 0x0080),
    RegisterRange("SLPCTL1", "SleepCtrl1", 0x0081),
    RegisterRange("RSVD", "Reserved", 0x0083, 0x0086),
    RegisterRange("CDCTL0", "CollisionDetectCtrl0", 0x0087),
    RegisterRange("RSVD", "Reserved", 0x0089, 0x009F),
    RegisterRange("SQICTL", "SQICtrl", 0x00A0),
    RegisterRange("SQISTS0", "SQIStatus0", 0x00A1),
    RegisterRange("RSVD", "Reserved", 0x00A3, 0x00A9),
    RegisterRange("SQICFG0", "SQICfg0", 0x00AA),
    RegisterRange("SQICFG2", "SQICfg2", 0x00AC),
    RegisterRange("RSVD", "Reserved", 0x00AD, 0x00D4), #NOTE: Corrected 0xAE to 0xAD, seems to be an error in the datasheet from microchip
    RegisterRange("ANALOG5", "AnalogCtrl5", 0x00D5),
    RegisterRange("RSVD", "Reserved", 0x00D7, 0xC9FF),
    RegisterRange("MIDVER", "MapIDAndVersion", 0xCA00),
    RegisterRange("PLCA_CTRL0", "PLCACtrl0", 0xCA01),
    RegisterRange("PLCA_CTRL1", "PLCACtrl1", 0xCA02),
    RegisterRange("PLCA_STS", "PLCAStatus", 0xCA03),
    RegisterRange("PLCA_TOTMR", "PLCATxOpportunityTimer", 0xCA04),
    RegisterRange("PLCA_BURST", "PLCABurstMode", 0xCA05),
    ]

    MMS10 = [
    RegisterRange("RSVD", "Reserved", 0x0000, 0x0080),
    RegisterRange("QTXCFG", "QueueTxCfg", 0x0081),
    RegisterRange("QRXCFG", "QueueRxCfg", 0x0082),
    RegisterRange("RSVD", "Reserved", 0x0086, 0x0087),
    RegisterRange("PADCTRL", "PadCtrl", 0x0088), #NOTE: This is not displayed in the overall reg description, but is mentioned elsewhere in the datasheet. Most likely an error in the datasheet from microchip
    RegisterRange("CLKOCTL", "ClkOutputCtrl", 0x0089),
    RegisterRange("MISC", "Miscellaneous", 0x008C),
    RegisterRange("RSVD", "Reserved", 0x0090, 0x0093),
    RegisterRange("DEVID", "DeviceID", 0x0094),
    RegisterRange("BUSPCS", "BusParityCtrlAndStatus", 0x0096),
    RegisterRange("CFGPRTCTL", "CfgProtCtrl", 0x0099),
    RegisterRange("RSVD", "Reserved", 0x009D, 0x00FF),
    RegisterRange("ECCCTRL", "SRAMErrCorrectionCodeCtrl", 0x0100),
    RegisterRange("ECCSTS", "SRAMErrCorrectionCodeStatus", 0x0101),
    RegisterRange("ECCFLTCTRL", "SRAMErrCorrectionCodeFaultInjectionCtrl", 0x0102),
    RegisterRange("RSVD", "Reserved", 0x0106, 0x01FF),
    RegisterRange("EC0CTRL", "EvtCapt0Ctrl", 0x0200),
    RegisterRange("EC1CTRL", "EvtCapt1Ctrl", 0x0201),
    RegisterRange("EC2CTRL", "EvtCapt2Ctrl", 0x0202),
    RegisterRange("EC3CTRL", "EvtCapt3Ctrl", 0x0203),
    RegisterRange("ECRDSTS", "EvtCaptReadStatus", 0x0204),
    RegisterRange("ECTOT", "EvtCaptTotCnt", 0x0205),
    RegisterRange("ECCLKSH", "EvtCaptClkSecHigh", 0x0206),
    RegisterRange("ECCLKSL", "EvtCaptClkSecLow", 0x0207),
    RegisterRange("ECCLKNS", "EvtCaptClkNanoSec", 0x0208),
    RegisterRange("ECRDTS0", "EvtCaptReadTime0", 0x0209),
    RegisterRange("ECRDTS1", "EvtCaptReadTime1", 0x020A),
    RegisterRange("ECRDTS2", "EvtCaptReadTime2", 0x020B),
    RegisterRange("ECRDTS3", "EvtCaptReadTime3", 0x020C),
    RegisterRange("ECRDTS4", "EvtCaptReadTime4", 0x020D),
    RegisterRange("ECRDTS5", "EvtCaptReadTime5", 0x020E),
    RegisterRange("ECRDTS6", "EvtCaptReadTime6", 0x020F),
    RegisterRange("ECRDTS7", "EvtCaptReadTime7", 0x0210),
    RegisterRange("ECRDTS8", "EvtCaptReadTime8", 0x0211),
    RegisterRange("ECRDTS9", "EvtCaptReadTime9", 0x0212),
    RegisterRange("ECRDTS10", "EvtCaptReadTime10", 0x0213),
    RegisterRange("ECRDTS11", "EvtCaptReadTime11", 0x0214),
    RegisterRange("ECRDTS12", "EvtCaptReadTime12", 0x0215),
    RegisterRange("ECRDTS13", "EvtCaptReadTime13", 0x0216),
    RegisterRange("ECRDTS14", "EvtCaptReadTime14", 0x0217),
    RegisterRange("ECRDTS15", "EvtCaptReadTime15", 0x0218),
    RegisterRange("RSVD", "Reserved", 0x021C, 0x021E),
    RegisterRange("PACYC", "PhaseAdjusterCycles", 0x021F),
    RegisterRange("PACTRL", "PhaseAdjusterCtrl", 0x0220),
    RegisterRange("EG0STNS", "Evt0StartTimeNanoSec", 0x0221),
    RegisterRange("EG0STSECL", "Evt0StartTimeSecLow", 0x0222),
    RegisterRange("EG0STSECH", "Evt0StartTimeSecHigh", 0x0223),
    RegisterRange("EG0PW", "Evt0PulseWidth", 0x0224),
    RegisterRange("EG0IT", "Evt0IdleTime", 0x0225),
    RegisterRange("EG0CTL", "EvtGenerator0Ctrl", 0x0226),
    RegisterRange("EG1STNS", "Evt1StartTimeNanoSec", 0x0227),
    RegisterRange("EG1STSECL", "Evt1StartTimeSecLow", 0x0228),
    RegisterRange("EG1STSECH", "Evt1StartTimeSecHigh", 0x0229),
    RegisterRange("EG1PW", "Evt1PulseWidth", 0x022A),
    RegisterRange("EG1IT", "Evt1IdleTime", 0x022B),
    RegisterRange("EG1CTL", "EvtGenerator1Ctrl", 0x022C),
    RegisterRange("EG2STNS", "Evt2StartTimeNanoSec", 0x022D),
    RegisterRange("EG2STSECL", "Evt2StartTimeSecLow", 0x022E),
    RegisterRange("EG2STSECH", "Evt2StartTimeSecHigh", 0x022F),
    RegisterRange("EG2PW", "Evt2PulseWidth", 0x0230),
    RegisterRange("EG2IT", "Evt2IdleTime", 0x0231),
    RegisterRange("EG2CTL", "EvtGenerator2Ctrl", 0x0232),
    RegisterRange("EG3STNS", "Evt3StartTimeNanoSec", 0x0233),
    RegisterRange("EG3STSECL", "Evt3StartTimeSecLow", 0x0234),
    RegisterRange("EG3STSECH", "Evt3StartTimeSecHigh", 0x0235),
    RegisterRange("EG3PW", "Evt3PulseWidth", 0x0236),
    RegisterRange("EG3IT", "Evt3IdleTime", 0x0237),
    RegisterRange("EG3CTL", "EvtGenerator3Ctrl", 0x0238),
    RegisterRange("PPSCTL", "OnePulsePerSecCtrl", 0x0239),
    RegisterRange("SEVINTEN", "SyncEvtInterruptEnable", 0x023A),
    RegisterRange("SEVINTDIS", "SyncEvtInterruptDisable", 0x023B),
    RegisterRange("SEVIM", "SyncEvtInterruptMaskStatus", 0x023C),
    RegisterRange("SEVSTS", "SyncEvtStatus", 0x023D),
    ]

    MMS_MAP = {
        0: {'name': "StdCtrlAndStatus", 'regs': MMS0},
        1: {'name': "MAC", 'regs': MMS1},
        2: {'name': "PHYPCS", 'regs': MMS2},
        3: {'name': "PHYPMA/PMD", 'regs': MMS3},
        4: {'name': "PHYVndSpecificAndPLCA", 'regs': MMS4},
        5: {'name': "PHYAutoNegotiation", 'regs': None},
        6: {'name': "PHYPowerUnit", 'regs': None},
        7: {'name': "Reserved", 'regs': None},
        8: {'name': "Reserved", 'regs': None},
        9: {'name': "Reserved", 'regs': None},
        10: {'name': "MiscRegDesc", 'regs': MMS10},
        11: {'name': "VndSpecific", 'regs': None},
        12: {'name': "VndSpecific", 'regs': None},
        13: {'name': "VndSpecific", 'regs': None},
        14: {'name': "VndSpecific", 'regs': None},
        15: {'name': "VndSpecific", 'regs': None},
    }


    @classmethod
    def get_reg(cls, mms, addr):
        mms = cls.MMS_MAP.get(mms)

        if not mms:
            return "Unknown"

        reg_info = None
        if mms['regs']:
                for reg in mms['regs']:
                        if reg == addr:
                                reg_info = reg
                                break

        reg_name = "" if not reg_info else (reg_info.description if reg_info.description != "" else reg_info.name)
        return f"({mms['name']}::{reg_name})"
