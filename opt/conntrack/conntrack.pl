#!/usr/bin/perl
# Door Chris Gralike
# Het script verwerkt de  conntrack en rapporteert dit naar firewall.php script.
# TODO:
#   - Update IPTables als een nieuwe versie beschikbaar is.
#   - Kill verbinding als daarom verzocht wordt
#   - Interface is mysql database

use strict;                     # gebruik strict
use warnings;                   # gebruik warnings
use DBI;                        # gebruik DBI
use Digest::MD5 qw(md5_hex);    # gebruik md5 hashing
use Data::Dumper;               # gebruik datadumper
use DateTime;                   # gebruik datetime


# declareer globale vars;
my %sessioncache;       # stores identified sessions
my $marker              = 2;  # Used to track marked sessions
my $db                  = DBI->connect("DBI:mysql:database=firewall;host=IP.IP.IP.IP",
                               "[SQLUSER]", "[SQLPASSWORD]",{'RaiseError' => 1});
my $datetime            = localtime();

# Start een infinite while loop.
print("$datetime: \tEntering infinite main loop\n");
while(1) {
        $datetime = localtime();
        # Open een database connectie
        print("$datetime: \tEvaluating database connection\n");
        until( $db->ping ){
           warn "$datetime: \tCan't connect: $DBI::errstr. Pausing before retrying.\n";
           sleep( 5 );
           eval { $db = DBI->connect("DBI:mysql:database=firewall;host=IP.IP.IP.IP",
                               "[SQLUSER]", "[SQLPASSWORD]",{'RaiseError' => 1});
        }

        #
        print("$datetime: \tDatabase connection available\n");

        # Doe eerst een truncate op het actieve table nadat de verbinding verbroken is geweest
        # Altijd schoon beginnen met de activiteiten
        print("$datetime: \tTruncating active table for reset\n");
        eval { $db->do("truncate table active"); 1; };

        # Vang ventuele events op en breng het script terug naar de init fase
        # begin opnieuw...
        print("$datetime: \tStarting firewalld\n");
        system('/opt/conntrack/startfw.sh');

        print("$datetime: \tEntering monitoring loop\n");

        eval {
            while(1) {

            $datetime = localtime();

            # Flip Flop marker wordt gebruikt om inactieve
            # sessies in onze cache te vinden zodat ze geschoond worden;
            if($marker == 1){ $marker = 2; }else{ $marker = 1; }

            # Pad naar de contrack proc file
            my $cfp = '/proc/net/nf_conntrack';

            # Open de contrack file voor lezen met UTF8 als output
            open(my $fh, "<:encoding(UTF-8)", $cfp) || die "$datetime: \tCannot open file for reading $!";

            # Loop door de entries in nf_conntrack;
            # En verwerk deze en sla deze op in onze database
            while (my $row = <$fh>) {

                    # Breek elke rij op in velden met waarden
                    # Dit zodat we snel kunnen filteren
                    my @fields = split /\s/, $row;

                    # Omdat de split op elk type whitespace
                    # plaatsvindt lopen we risico op meerdere
                    # undefined fields door opeenvolgende whitespaces
                    # schoon the array van deze 'undefs' door te greppen
                    # op alles dat niet leeg is :)
                    @fields = grep(/.+/, @fields);

                    # Sommige velden bevatten sleutel = waarde combinaties.
                    # We willen deze sleutels verwijderen omdat ze altijd op
                    # dezelfde plaats staan. Daarom zoeken s/ we naar elke string
                    # die ^ begint met een of meerdere karakters . gevolgd door
                    # een = teken. Deze gevonden string vervangen we vervolgens
                    # met niks. //
                    for (@fields) {
                            s/^.+=//
                    }

                    # Als de bron van de connectie van het type tcp is en niet
                    # afkomstig is van de server zelf, zijn localhost, een ipv6
                    # bron of een broadcast addres is, verwerk deze dan als
                    # nieuwe sessie.
                    if( $fields[2] eq 'tcp' &&
                        $fields[6] !~ /^10.255/ &&
                        $fields[6] !~ /^127.0/ &&
                        $fields[6] !~ /^[0-9]{4}:/ &&
                        $fields[6] !~ /^224.0/ ) {

                            # We berekenen een unieke sessieId op basis van sourceip en destination port
                            # Op deze manier concat we direct een veelheid van verbindingen (calls) op een
                            # poort naar één ingang ipv 100en (bijvoorbeeld bij het openen van een webpagina).
                            my $sessID = md5_hex($fields[9].$fields[6]);

                            # Creeer tijddatum van nu op basis van epoch.
                            my $dt = DateTime->now;
                            $dt->set_time_zone('Europe/Amsterdam');

                            # Beoordeel of we deze sessie al eens hebben geregistreerd zo niet sla deze als
                            # nieuwe sessie op in onze sessiecache.
                            if ( exists $sessioncache{$sessID} ) {
                                    # mark the session with new timestamp
                                    $sessioncache{$sessID}{'ff'} = $marker;
                                    $sessioncache{$sessID}{'last'} = $dt->hms;
                                    #print("$datetime: \t Updating...\n");

                                    # Update de logging table
                                    eval { $db->do("update logging set last_seen = ? where sessionId = ?", undef, $dt->hms, $sessID); 1; } or die "$datetime: \tQuery failed: $@ !\n";

                                    # Update de active table
                                    eval { $db->do("update active set last_seen = ? where sessionId = ?", undef, $dt->hms, $sessID); 1; } or die "$datetime: \tQuery failed: $@ !\n";

                            }else{
                                    # Registreer de sessie in onze cache.
                                    $sessioncache{$sessID}{'ff'} = $marker;
                                    $sessioncache{$sessID}{'first'} = $dt->hms;
                                    $sessioncache{$sessID}{'last'} = $dt->hms;
                                    $sessioncache{$sessID}{'state'} = $fields[5];
                                    $sessioncache{$sessID}{'reply'} = $fields[14];
                                    $sessioncache{$sessID}{'source'} = $fields[6];
                                    $sessioncache{$sessID}{'sport'} = $fields[8];
                                    $sessioncache{$sessID}{'dport'} = $fields[9];
                                    $sessioncache{$sessID}{'meta'} = $fields[16];

                                    # Doe een database insert in de tabel actief
                                    eval { $db->do("insert into active(sessionId,
                                                                date_seen,
                                                                first_seen,
                                                                last_seen,
                                                                conn_state,
                                                                conn_reply,
                                                                conn_source,
                                                                conn_sport,
                                                                conn_dport,
                                                                conn_meta)
                                                         values(?,?,?,?,?,?,?,?,?,?)",
                                             undef,
                                             $sessID,
                                             $dt->dmy,
                                             $sessioncache{$sessID}{'first'},
                                             $sessioncache{$sessID}{'last'},
                                             $sessioncache{$sessID}{'state'},
                                             $sessioncache{$sessID}{'reply'},
                                             $sessioncache{$sessID}{'source'},
                                             $sessioncache{$sessID}{'sport'},
                                             $sessioncache{$sessID}{'dport'},
                                             $sessioncache{$sessID}{'meta'}); } or die "$datetime: \tUnable to insert into database $@\n";

                                    # Sla de sessie op in ons LOG maar:
                                    # Alleen als het !geen! OEM agent is willen we
                                    # logging hebben. Dit weten we op basis van de
                                    # poort 4903

                                    if( $sessioncache{$sessID}{'dport'} ne '4903' ) {

                                    eval { $db->do("insert into logging(sessionId,
                                                                date_seen,
                                                                first_seen,
                                                                last_seen,
                                                                conn_state,
                                                                conn_reply,
                                                                conn_source,
                                                                conn_sport,
                                                                conn_dport,
                                                                conn_meta)
                                                         values(?,?,?,?,?,?,?,?,?,?)",
                                             undef,
                                             $sessID,
                                             $dt->dmy,
                                             $sessioncache{$sessID}{'first'},
                                             $sessioncache{$sessID}{'last'},
                                             $sessioncache{$sessID}{'state'},
                                             $sessioncache{$sessID}{'reply'},
                                             $sessioncache{$sessID}{'source'},
                                             $sessioncache{$sessID}{'sport'},
                                             $sessioncache{$sessID}{'dport'},
                                             $sessioncache{$sessID}{'meta'}); } or die "$datetime: \tUnable to insert into database! $@\n";
                                    }
                            }
                    }
            }

            # Valideer de sessies in het cache, als marker niet overeenkomt dan
            # moeten we deze sessie verwijderen uit het cache.
            foreach my $session ( sort keys %sessioncache ) {

                    # Markeer de van de marker afwijkende sessies als verlopen
                    # Update de database tables met deze informatie
                    # deze worden de tweede itteratie verwijderd uit het cache.
                    if( $sessioncache{$session}{'ff'} != $marker){
                            eval { $db->do("delete from active where sessionId = ?", undef, $session); 1; } or do {
                            print "$datetime: \tDelete failed: $@ ?\n "; };
                            undef $sessioncache{$session}; #undefine de inner hash
                            delete $sessioncache{$session}; #delete entry uit hash
                    }



            #   print Dumper \%sessioncache;
            }


            # Controleer of er werk gedaan moet worden zoals het updaten
            # van de IPtables


            # neem elke seconde een sample
            sleep(1);
        }



        }; ## Eval in code
        warn "$datetime: \tMonitoring aborted by error: $@\n" if $@;

        # Kill the firewall;
        #
        print("$datetime: \tStopping the firewalld\n");

        #@args = ('systemctl','stop','firewalld');
        #system(@args) == 0 or die` "system @args failed: $?";
        system('/opt/conntrack/stopfw.sh');
        print("$datetime: \tStopped firewalld\n");

        ### Korte Pauze zodat we de database niet overhitten
        sleep 2;
}
exit;
#EOF
