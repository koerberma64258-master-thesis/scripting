#!/bin/bash

# postfix shell-based filter, see http://www.postfix.org/FILTER_README.html
# arguments: /path/to/script -f sender recipients...

# external programs and path definitions
SENDMAIL="/usr/sbin/sendmail -G -i" # no "-t" here!
LOGGER="/usr/sbin/postlog -t postfix/myFilter"
POSTTLSFINGER="/usr/sbin/posttls-finger"
TMPFILE="/var/spool/filter/in.$$"
CAPATH='/etc/ssl/certs/'

# exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# clean up when done or when aborting
trap "rm -f $TMPFILE" 0 1 2 3 15

echo "Start filter ($@), $TMPFILE" | $LOGGER
cat >$TMPFILE || {
    echo "Failed to save mail to file $TMPFILE" | $LOGGER
    echo 'Cannot save mail to file'
    exit $EX_TEMPFAIL
}
subject=$(grep --max-count 1 "^Subject:" $TMPFILE)

# create a sorted list of unique domain names (recipients)
recipients=${@:4}
domains=()
for recipient in $recipients
do  # take the part after the '@'
    domain=$(echo "$recipient" | cut -d'@' -f2)
    domains+=("$domain")
done
domains2check=$(echo "${domains[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')
echo "domains to check: ${domains2check[@]}" | $LOGGER

# identify the domain to be tested
# incoming mails are also processed by the filter
myDomain=$(dnsdomainname)
senderdomain=$(echo "$2" | cut -d'@' -f2)
incomingMail=false
if [[ $senderdomain != $myDomain ]]; then
    domains2check=($senderdomain)
    incomingMail=true
fi

# requested rating is a keyword and must be first in the subject
# if so then save it to $reqRating and remove it from subject
# keyword recognition only for outgoing mails
# otherwise removing the keyword would destroy the DKIM signature
# remove keyword with 'sed' (not yet with base64 encoded strings)
reqRating='no'
regexNormalString='^Subject: \{(\S+)\}'
regexQuotedString='^Subject: =\?([^\?]+)\?Q\?=7(B|b)([^_]+)=7(D|d)_'
regexBase64String='^Subject: =\?[^\?]+\?B\?(\S+)\?='
if [[ $incomingMail = false ]]; then
    if [[ $subject =~ $regexNormalString ]]; then
        reqRating=${BASH_REMATCH[1],,}
        sed -i -E "s/$regexNormalString/Subject: /" $TMPFILE
    elif [[ $subject =~ $regexQuotedString ]]; then
        charset=${BASH_REMATCH[1]}
        reqRating=${BASH_REMATCH[2],,}
        sed -i -E "s/$regexQuotedString/Subject: =\?$charset\?Q\?/" $TMPFILE
    elif [[ $subject =~ $regexBase64String ]]; then
        # decode subject with base64 before keyword detection
        decoded=$(echo "${BASH_REMATCH[1]}" | base64 --decode)
        keywordRegex='^\{(\S+)\}'
        [[ $decoded =~ $keywordRegex ]] && reqRating=${BASH_REMATCH[1],,}
    fi
fi

# execute connection test for each recipient
lowestRating=-1
lowestRatingDomain=''
lowestRatingParams=''
for domain2check in $domains2check
do  # production: test only if incomingMail = false and reqRating != 'no'
    echo "Test domain $domain2check ($@; reqRating: $reqRating; incomingMail: $incomingMail)" | $LOGGER
    connection=$($POSTTLSFINGER -l dane-only -P $CAPATH -L summary -c -- $domain2check)
    # posttls-finger params (http://www.postfix.org/posttls-finger.1.html)
    # * -l dane-only:  test DANE but falls back to secure by default
    #                  therefore $NoTlsa and $DnsInsecure are used
    # * -P CApath/:    by default no public CAs are trusted.
    #                  Use trusted certs on this systems for the test.
    # * -L summary:    log only summary
    # * -c:            disable SMTP chat logging
    # * --:            end of argument list
    # * $domain2check: domain name or system name to check

    # now parse the output of posttls-finger

    # check for DANE errors
    [[ $connection =~ 'no TLSA records found' ]] && NoTlsa=true || NoTlsa=false
    [[ $connection =~ 'MX RRset insecure' ]] && DnsInsecure=true || DnsInsecure=false

    # parse summary line, example:
    # Verified TLS connection established to example.org[198.51.100.11]:25: \
    # TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits)
    line=$(echo $connection | sed 's/posttls-finger: /\n/g' | grep 'TLS connection established')
    regex='(\S+) TLS connection established to (\S+): (\S+) with cipher (\S+)'
    [[ $line =~ $regex ]]
    conRating=${BASH_REMATCH[1]}
    server=${BASH_REMATCH[2]}
    TLSv=${BASH_REMATCH[3]}
    cipher=${BASH_REMATCH[4]}
    echo "Connected to $domain2check ($server): $conRating TLS with $TLSv ($cipher)" | $LOGGER

    TLSvAll="SSLv2 SSLv3 TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
    TLSvStrong="TLSv1.2 TLSv1.3"
    TLSvMedium="TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"

    # classify connection parameters in an overall security rating
    ratings=("unknown" "low" "normal low" "normal high" "secure")
    #        0         1     2            3             4
    rating=0
    # test $item is in $list: $list =~ (^|[[:space:]])$item($|[[:space:]])
    if [[ ${conRating,,} = 'verified' && $NoTlsa = false && $DnsInsecure = false && $TLSvStrong =~ (^|[[:space:]])$TLSv($|[[:space:]]) ]]; then
        # secure: verified domain and no TLSA/DNSSEC issues
        rating=4
    elif [[ (${conRating,,} = 'verified' || ${conRating,,} = 'trusted') && $TLSvMedium =~ (^|[[:space:]])$TLSv($|[[:space:]]) ]]; then
        # normal high: transport encryption with trusted certificate but no DANE
        rating=3
    elif [[ ${conRating,,} = 'untrusted' ]]; then
        # normal low: transport encryption
        rating=2
    else
        # low: maybe cleartext or other problem
        # raise error
        echo "failed to determine security level (connection to $domain2check)" | $LOGGER
        echo $connection | $LOGGER
        rating=1
    fi

    echo "Overall security rating for the connection to $domain2check: ${ratings[$rating]}" | $LOGGER

    # determine lowest rating
    if [[ $lowestRating = -1 || $rating < $lowestRating ]]; then
        lowestRating=$rating
        lowestRatingDomain=$domain2check
        lowestRatingParams="Domain $domain2check; Bewertung ${ratings[$rating]}; Schluesselwort $reqRating; Verbindung $conRating; TLS Version $TLSv"
    fi
done

# reject mail if requested rating (keyword) and rating not match
if [[ $incomingMail = true ]]; then
    # pass, incomming mail
    echo "Receive mail anyway from $senderdomain" | $LOGGER
elif [[ $rating = 4 ]]; then
    # pass, connection is secure
    echo 'Connection is secure, send mail' | $LOGGER
elif [[ $reqRating = 'secure' ]]; then
    # reject, connection is below requested rating (below secure)
    echo 'reject message (not secure)' | $LOGGER
    echo "Es ist nicht moeglich, eine sichere Verbindung zum Zielserver der Domain $lowestRatingDomain aufzubauen."
    echo 'Die E-Mail wurde deshalb nicht versendet.'
    echo "Details: $lowestRatingParams"
    exit $EX_UNAVAILABLE
elif [[ $reqRating = 'encrypted' && $rating = 3 ]]; then
    # pass, reqRating and rating match
    echo "Connection is encrypted, send mail" | $LOGGER
elif [[ $reqRating = 'encrypted' ]]; then
    # reject, connection is below requested rating (below encrypted)
    echo 'reject message (not encrypted)' | $LOGGER
    echo "Es ist nicht moeglich, eine verschluesselte Verbindung zum Zielserver der Domain $lowestRatingDomain aufzubauen."
    echo 'Die E-Mail wurde deshalb nicht versendet.'
    echo "Details: $lowestRatingParams"
    exit $EX_UNAVAILABLE
elif [[ $reqRating = 'no' ]]; then
    # pass, since no rating was requested
    echo "No rating requested, send mail anyway" | $LOGGER
else
    # reject, unknown reqRating
    echo "reject message to (domain $lowestRatingDomain - unknown reqRating)" | $LOGGER
    echo "Das folgende Schluesselwort wurde nicht erkannt: $reqRating."
    echo 'Die E-Mail wurde deshalb nicht versendet.'
    echo "Details: $lowestRatingParams"
    exit $EX_UNAVAILABLE
fi

# return mail to incoming queue via sendmail
# $@ looks like "-f sender@example.net -- receiver@example.org receiver2@example.com"
$SENDMAIL "$@" <$TMPFILE
exit $?
