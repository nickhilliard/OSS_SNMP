<?php

/*
    Copyright (c) 2019, Nick Hilliard. All rights reserved.

    This file is part of the OSS_SNMP package.

        Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

        * Redistributions of source code must retain the above copyright
          notice, this list of conditions and the following disclaimer.
        * Redistributions in binary form must reproduce the above copyright
          notice, this list of conditions and the following disclaimer in the
          documentation and/or other materials provided with the distribution.
        * Neither the name of Open Source Solutions Limited nor the
          names of its contributors may be used to endorse or promote products
          derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

namespace OSS_SNMP\MIBS;

/**
 * A class for extracting FDB information from L2 bridges.
 *
 * @copyright Copyright (c) 2012, Open Source Solutions Limited, Dublin, Ireland
 * @author Nick Hilliard <nick@foobar.org>
 */
class FDB extends \OSS_SNMP\MIB
{
    # ifDescr
    const OID_IFDESCR  = '.1.3.6.1.2.1.2.2.1.2';

    # dot1dBasePortIfIndex
    const OID_DOT1DBASEPORTIFINDEX  = '.1.3.6.1.2.1.17.1.4.1.2';

    # dot1qVlanFdbId
    const OID_DOT1QVLANFDBID        = '.1.3.6.1.2.1.17.7.1.4.2.1.3';

    # dot1qTpFdbPort
    const OID_DOT1QTPFDBPORT        = '.1.3.6.1.2.1.17.7.1.2.2.1.2';

    # dot1dTpFdbPort
    const OID_DOT1DTPFDBPORT        = '.1.3.6.1.2.1.17.4.3.1.2';

    # dot1dTpFdbAddress
    const OID_DOT1DTPFDBADDRESS     = '.1.3.6.1.2.1.17.4.3.1.1';

    # jnxExVlanTag
    const OID_JNXEXVLANTAG          = '.1.3.6.1.4.1.2636.3.40.1.5.1.5.1.5';

    # jnxL2aldVlanTag
    const OID_JNXL2ALDVLANTAG       = '.1.3.6.1.4.1.2636.3.48.1.3.1.1.3';

    # jnxL2aldVlanFdbId
    const OID_JNXL2ALDVLANFDBID     = '.1.3.6.1.4.1.2636.3.48.1.3.1.1.5';

    /**
     * Gets the ifIndex to ifDescr array
     *
     * E.g.:
     *    [] => Array
     *        (
     *            [1] => 'Ethernet1',
     *            [2] => 'Ethernet1'
     *        )
     *
     * @return array associative array of ifIndexes pointing to the ifDescr entry
     */
    public function getifDescr()
    {
        return $this->getSNMP()->walk1d(self::OID_IFDESCR);
    }

    /**
     * Gets the ifIndex to dot1d baseport array
     *
     * E.g.:
     *    [] => Array
     *        (
     *            [1] => 1001,
     *            [2] => 1002
     *        )
     *
     * @return array Associate array of ifIndex pointing to their associated dot1dBasePort entry
     */
    public function getBasePortIfIndex()
    {
        return $this->getSNMP()->walk1d(self::OID_DOT1DBASEPORTIFINDEX);
    }

    /**
     * Gets the vlanIndex to dot1d vlan tag array
     *
     * E.g.:
     *    [] => Array
     *        (
     *            [10] => 10,
     *            [30] => 30,
     *            [70] => 70
     *        )
     *
     * @return array Associate array of vlanIndex pointing to their associated dot1d vlan tag
     */
    public function getvlanmapping()
    {
        try {
            $foo = $this->getSNMP()->walk1d(self::OID_DOT1QVLANFDBID.".0");
        } catch (\Exception $e) {
            $foo = array ();
        }
        
        return $foo;
    }


    public function trawl_switch_snmp ($vlan) {

        $debug = 1;
        $qbridge_support = 1;
        $host = $this->getSNMP()->getHost();

        $oids = array (
                                    
            'sysDescr'              => '.1.3.6.1.2.1.1.1',
            'ifDescr'               => '.1.3.6.1.2.1.2.2.1.2',
            'dot1dBasePortIfIndex'  => '.1.3.6.1.2.1.17.1.4.1.2',
            'dot1qVlanFdbId'        => '.1.3.6.1.2.1.17.7.1.4.2.1.3',
            'dot1qTpFdbPort'        => '.1.3.6.1.2.1.17.7.1.2.2.1.2',
            'dot1dTpFdbPort'        => '.1.3.6.1.2.1.17.4.3.1.2',
            'dot1dTpFdbAddress'     => '.1.3.6.1.2.1.17.4.3.1.1',
            'jnxExVlanTag'          => '.1.3.6.1.4.1.2636.3.40.1.5.1.5.1.5',
            'jnxL2aldVlanTag'       => '.1.3.6.1.4.1.2636.3.48.1.3.1.1.3',
            'jnxL2aldVlanFdbId'     => '.1.3.6.1.4.1.2636.3.48.1.3.1.1.5',
        );

        if ($debug) { print "DEBUG: $host: started query process\n"; }

        $sysdescr = $this->snmpwalk2hash($oids['sysDescr'], false, false, false);

        if (preg_match('/Cisco\s+(NX-OS|IOS)/', $sysdescr[0])) {
            if (!defined ($vlan) || $vlan == 0) {
                print "ERROR: $host: must specify VLAN for Cisco IOS/NX-OS switches\n";
                return;
            }
            if ($debug) { print "WARNING: $host: using community\@vlan hack to handle broken SNMP implementation\n"; }
            $snmpcommunity .= '@'.$vlan;
        }

        $ifindex = $this->snmpwalk2hash($oids['ifDescr'], false, false, false);
        if (!$ifindex) {
            print "WARNING: $host: cannot read ifDescr. Not processing $host further.\n";
            return;
        }

        $interfaces = $this->snmpwalk2hash($oids['dot1dBasePortIfIndex'], false, false, false);
        if (!$interfaces) {
            print "WARNING: $host: cannot read dot1dBasePortIfIndex. Not processing $host further.\n";
            return;
        }

        if ($debug) { print "DEBUG: $host: pre-emptively trying Juniper jnxExVlanTag to see if we're on a J-EX box (" . $oids['jnxExVlanTag'] . ")\n"; }
        
        $vlanmapping = $this->snmpwalk2hash($oids['jnxExVlanTag'], false, false, false);

        # if jnxExVlanTag returns something, then this is a juniper and we need to
        # handle the interface mapping separately on these boxes
        if ($vlanmapping) {
            $juniperexmapping = 1;
            if ($debug) { print "DEBUG: $host: looks like this is a Juniper EX\n"; }
        } else {
            if ($debug) { print "DEBUG: $host: this isn't a Juniper EX\n"; }
        }

        if (!$vlanmapping) {
            # Juniper KB32532:
            #
            # We start out with two arrays, jnxL2aldVlanTag and jnxL2aldVlanFdbId.  We need to
            # end up with a mapping from the value of jnxL2aldVlanFdbId pointing to the
            # value of jnxL2aldVlanTag.
            #
            # jnxL2aldVlanTag.3 = 1
            # jnxL2aldVlanTag.4 = 10
            # jnxL2aldVlanTag.5 = 20
            # jnxL2aldVlanFdbId.3 = 196608
            # jnxL2aldVlanFdbId.4 = 262144
            # jnxL2aldVlanFdbId.5 = 327680
            #
            # This gets mapped to
            # array (
            #	196608 => 1,
            #	262144 => 10,
            #	327680 => 20
            # )
            $jnxL2aldvlantag = $this->snmpwalk2hash($oids['jnxL2aldVlanTag'], false, false, false);
            if ($jnxL2aldvlantag) {
                if ($debug) { print "DEBUG: $host: looks like this is a Juniper EX running an ELS image\n"; }
                $jnxL2aldvlanid = $this->snmpwalk2hash($oids['jnxL2aldVlanFdbId'], false, false, false );

                foreach (array_keys($jnxL2aldvlantag) as $index) {
                    $vlanmapping[$jnxL2aldvlanid[$index]] = $jnxL2aldvlantag[$index];
                }

                if (!$vlanmapping) {
                    print "WARNING: $host: Juniper ELS image detected but VLAN mapping retrieval failed. Not processing $host further.\n";
                    return;
                }
            } else {
                if ($debug) { print "DEBUG: $host: this isn't a Juniper running an ELS image\n"; }
            }
        }

        # attempt to use Q-BRIDGE-MIB.
        if ($vlan && $qbridge_support) {
            if ($debug) { print "DEBUG: $host: attempting to retrieve dot1qVlanFdbId mapping (".$oids['dot1qVlanFdbId'].")\n"; }

            if (!$vlanmapping) {
                $vlanmapping = $this->snmpwalk2hash($oids['dot1qVlanFdbId'].".0", false, false, false);
            }
            
            # At this stage we should have a dot1qVlanFdbId mapping, but
            # some switches don't support it (e.g.  Dell F10-S4810), so
            # if it doesn't exist we'll attempt Q-BRIDGE-MIB with the
            # VLAN IDs instead of mapped IDs.

            if ($vlanmapping) {    # if this fails too, Q-BRIDGE-MIB is out
                $vlan2idx = $this->array_reverse ($vlanmapping);
                $vlanid = $vlan2idx[$vlan];
                if ($debug) { print "DEBUG: $host: got mapping index: $vlan maps to $vlanid\n"; }
            } else {
                if ($debug) { print "DEBUG: $host: that didn't work either. attempting Q-BRIDGE-MIB with no fdb->ifIndex mapping\n"; }
                $vlanid = $vlan;
            }

            if ($debug) { print "DEBUG: $host: attempting Q-BRIDGE-MIB (".$oids['dot1qTpFdbPort'].".$vlanid)\n"; }
            $qbridgehash = $this->snmpwalk2hash($oids['dot1qTpFdbPort'].".".$vlanid, [$this, 'oid2mac'], false, false);

            if ($qbridgehash) {
                if ($debug) { print "DEBUG: $host: Q-BRIDGE-MIB query successful\n"; }
            } else {
                if ($debug) { print "DEBUG: $host: dot1qTpFdbPort.$vlanid failed - attempting baseline dot1qTpFdbPort subtree walk in desperation\n"; }

                # some stacks (e.g.  Comware) don't support mib walk for
                # dot1qTpFdbPort.$vlanid, so we'll attempt dot1qTpFdbPort instead, then
                # filter out all the unwanted entries.  This is inefficient and unusual, so
                # it's the last option attempted.

                $qbridgehash = $this->snmpwalk2hash($oids['dot1qTpFdbPort'], [$this, 'oid2mac'], false, $vlanid);

                if ($qbridgehash) {
                    if ($debug) { print "DEBUG: $host: Q-BRIDGE-MIB query ".($qbridgehash ? "successful" : "failed")."\n"; }
                }
                if ($debug) { print "DEBUG: $host: failed to retrieve Q-BRIDGE-MIB. falling back to BRIDGE-MIB\n"; }
            }
        } else {
            if ($debug && $qbridge_support) { print "DEBUG: $host: vlan not specified - falling back to BRIDGE-MIB for compatibility\n"; }
        }

        # special case: when the vlan is not specified, juniper EX boxes
        # return data on Q-BRIDGE-MIB rather than BRIDGE-MIB
        if (!$vlan && $juniperexmapping) {
            if ($debug) { print "DEBUG: $host: attempting special Juniper EX Q-BRIDGE-MIB query for unspecified vlan\n"; }
            $qbridgehash = $this->snmpwalk2hash($oids['dot1qTpFdbPort'], [$this, 'oid2mac'], false);
            if ($debug) {
                if ($qbridgehash) {
                    print "DEBUG: $host: Juniper EX Q-BRIDGE-MIB query successful\n";
                } else {
                    print "DEBUG: $host: failed Juniper EX Q-BRIDGE-MIB retrieval\n";
                }
            }            
        }

        # if vlan wasn't specified or there's nothing coming in from the
        # Q-BRIDGE mib, then use rfc1493 BRIDGE-MIB.
        if (($vlan && !$qbridgehash) || (!$vlan && !$juniperexmapping)) {
            if ($debug) { print "DEBUG: $host: attempting BRIDGE-MIB (".$oids['dot1dTpFdbPort'].")\n"; }
            $dbridgehash = $this->snmpwalk2hash($oids['dot1dTpFdbPort'], false, false, false);
            if ($debug and $dbridgehash) { print "DEBUG: $host: BRIDGE-MIB query successful\n"; }
        }

        # if this isn't supported, then panic.  We could probably try
        # community@vlan syntax, but this should be good enough.
        if (!$qbridgehash && !$dbridgehash) {
            print "WARNING: $host: cannot read BRIDGE-MIB or Q-BRIDGE-MIB. Not processing $host further.\n";
            return;
        }

        if ($dbridgehash) {
            $bridgehash2mac = $this->snmpwalk2hash($oids['dot1dTpFdbAddress'], false, [$this, 'normalize_mac'], false);
            $bridgehash = $dbridgehash;
            $maptable = $bridgehash2mac;
        } else {
            $bridgehash = $qbridgehash;
            $maptable = $qbridgehash;
        }

        foreach (array_keys($maptable) as $entry) {
            if (isset($ifindex[$interfaces[$bridgehash[$entry]]])) {
                $int = $ifindex[$interfaces[$bridgehash[$entry]]];
                if ($juniperexmapping && preg_match('/\.\d+$/', $int)) {
                    $int = preg_replace('/(\.\d+)$/','', $int);
                }
                if ($dbridgehash) {
                    $entry = $bridgehash2mac[$entry];
                }
                $macaddr[$int][] = $entry;
            }
        }

        return $macaddr;

    }

    public function snmpwalk2hash ($queryoid, $keycallback, $valuecallback, $keyfilter)
    {

        $index = count(explode ('.', $queryoid));
        try {
            $resultarray = $this->getSNMP()->subOidWalk($queryoid, $index, -1);
        } catch (\Exception $e) {
        }

        if (!$resultarray) {
            return;
        }

        foreach (array_keys($resultarray) as $returnoid) {

            $descr = $resultarray[$returnoid];

            # ignore all returned OIDs except those starting with $keyfilter
            if ($keyfilter) {
                if (!preg_match('/^($keyfilter)\./', $returnoid)) {
                    $returnoid = preg_replace('/^($keyfilter)\./', '', $returnoid);
                    continue;
                }
            }

            if ($keycallback) {
                $returnoid = $keycallback($returnoid);
            }
            if ($valuecallback) {
                $descr = $valuecallback($descr);
            }

            $returnhash[$returnoid] = $descr;
        }
        
        return ($returnhash);
    }

    # oid2mac: converts from dotted decimal format to contiguous hex

    function oid2mac ($mac)
    {
        $hextets = explode(".", $mac);

        $hexmac = '';
        foreach ($hextets as $hex) {
            $hexmac .= sprintf ('%02x', $hex);
        }
            
        return $hexmac;
    }


    function normalize_mac ($mac)
    {
        if (!isset ($mac)) {
            return;
        }
        
        # translate this OCTET_STRING to hexadecimal, unless already translated
        if ( strlen ($mac) != 12 ) {
                $mac = bin2hex(stripslashes($mac));
        }
    
        $mac = strtolower($mac);
    
        return ($mac);
    }

    public function array_reverse ($array)
    {

        if (!$array) {
            return;
        };

        foreach (array_keys($array) as $key) {
            $reverse[$array[$key]] = $key;
        }
    
        return $reverse;
    }

}
