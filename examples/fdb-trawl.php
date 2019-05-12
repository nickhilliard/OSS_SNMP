#! /usr/bin/php
<?php

require_once( dirname( __FILE__ ) . '/../OSS_SNMP/SNMP.php' );

$host = new \OSS_SNMP\SNMP( $argv[1], $argv[2] );

#echo "getifDescr {$argv[1]}: " . var_dump($host->useFDB()->getifDescr()) . "\n";

#echo "getBasePortIfIndex {$argv[1]}: " . var_dump($host->useFDB()->getBasePortIfIndex()) . "\n";

#echo "getvlanmapping {$argv[1]}: " . var_dump($host->useFDB()->getvlanmapping()) . "\n";

#var_dump($host->useFDB()->array_reverse (array ( "foo" => "bar", "blah" => "shite")));

#var_dump($host->useFDB()->oid2mac ("12.54.231.33.126.99"));

echo "trawl_switch_snmp {$argv[1]}: " . var_dump($host->useFDB()->trawl_switch_snmp(10)) . "\n";

exit( 0 );


