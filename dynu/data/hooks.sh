#!/usr/bin/env bashio

CONFIG_PATH=/data/options.json

SYS_CERTFILE=$(jq --raw-output '.lets_encrypt.certfile' $CONFIG_PATH)
SYS_KEYFILE=$(jq --raw-output '.lets_encrypt.keyfile' $CONFIG_PATH)

Dynu_ClientId=$(jq --raw-output '.oauth2.client' $CONFIG_PATH)
Dynu_Secret=$(jq --raw-output '.oauth2.secret' $CONFIG_PATH)
Dynu_Token=""
Dynu_EndPoint="https://api.dynu.com/v2"

# https://github.com/lukas2511/dehydrated/blob/master/docs/examples/hook.sh

deploy_challenge() {
	local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"
	
    # This hook is called once for every domain that needs to be
    # validated, including any alternative names you may have listed.
    #
    # Parameters:
    # - DOMAIN
    #   The domain name (CN or subject alternative name) being
    #   validated.
    # - TOKEN_FILENAME
    #   The name of the file containing the token to be served for HTTP
    #   validation. Should be served by your web server as
    #   /.well-known/acme-challenge/${TOKEN_FILENAME}.
    # - TOKEN_VALUE
    #   The token value that needs to be served for validation. For DNS
    #   validation, this is what you want to put in the _acme-challenge
    #   TXT record. For HTTP validation it is the value that is expected
    #   be found in the $TOKEN_FILENAME file.

	dns_dynu_add $DOMAIN $TOKEN_VALUE
	sleep 30
}

clean_challenge() {
	local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"
	
    # This hook is called after attempting to validate each domain,
    # whether or not validation was successful. Here you can delete
    # files or DNS records that are no longer needed.
    #
    # The parameters are the same as for deploy_challenge.

	dns_dynu_rm $DOMAIN $TOKEN_VALUE
}

deploy_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}" TIMESTAMP="${6}"

    # This hook is called once for each certificate that has been
    # produced. Here you might, for instance, copy your new certificates
    # to service-specific locations and reload the service.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    # - TIMESTAMP
    #   Timestamp when the specified certificate was created.

    cp -f "$FULLCHAINFILE" "/ssl/$SYS_CERTFILE"
	cp -f "$KEYFILE" "/ssl/$SYS_KEYFILE"
}

#Usage: add www.domain.com "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_dynu_add() {
	fulldomain=$1
	txtvalue=$2
	
	if [ -z "$Dynu_ClientId" ] || [ -z "$Dynu_Secret" ]; then
		Dynu_ClientId=""
		Dynu_Secret=""
		bashio::log.error "Dynu client id and/or secret are not specified."
		bashio::log.error "Please create you API client id and secret and try again."
		return 1
	fi

	if [ -z "$Dynu_Token" ]; then
		bashio::log.info "Getting Dynu token."
		if ! _dynu_authentication; then
			bashio::log.error "Can not get token."
		fi
	fi

	bashio::log.info "Detecting root zone"
	if ! _get_root "$fulldomain"; then
		bashio::log.info "Invalid domain."
		return 1
	fi

	bashio::log.info "Creating TXT record."
	if ! _dynu_rest POST "dns/$dnsId/record" "{\"domainId\":\"$dnsId\",\"nodeName\":\"$_node\",\"recordType\":\"TXT\",\"textData\":\"$txtvalue\",\"state\":true,\"ttl\":90}"; then
		return 1
	fi

	if ! _contains "$response" "200"; then
		bashio::log.error "Could not add TXT record."
		return 1
	fi

	return 0
}

#Usage: rm www.domain.com "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_dynu_rm() {
	fulldomain=$1
	txtvalue=$2

	if [ -z "$Dynu_ClientId" ] || [ -z "$Dynu_Secret" ]; then
		Dynu_ClientId=""
		Dynu_Secret=""
		bashio::log.error "Dynu client id and/or secret are not specified."
		bashio::log.error "Please create you API client id and secret and try again."
		return 1
	fi

	if [ -z "$Dynu_Token" ]; then
		bashio::log.info "Getting Dynu token."
		if ! _dynu_authentication; then
			bashio::log.error "Can not get token."
		fi
	fi

	bashio::log.debug "Detecting root zone."
	if ! _get_root "$fulldomain"; then
		bashio::log.error "Invalid domain."
		return 1
	fi

	bashio::log.info "Checking for TXT record."
	if ! _get_recordid "$fulldomain" "$txtvalue"; then
		bashio::log.error "Could not get TXT record id."
		return 1
	fi

	if [ "$_dns_record_id" = "" ]; then
		bashio::log.error "TXT record not found."
		return 1
	fi

	bashio::log.info "Removing TXT record."
	if ! _delete_txt_record "$_dns_record_id"; then
		bashio::log.error "Could not remove TXT record $_dns_record_id."
	fi

	return 0
}

#_acme-challenge.www.domain.com
#returns
# _node=_acme-challenge.www
# _domain_name=domain.com
_get_root() {
	domain=$1
	i=2
	p=1
	while true; do
		h="${domain//^\*\./}"
		if [ -z "$h" ]; then
			#not valid
			return 1
		fi

		if ! _dynu_rest GET "dns/getroot/$h"; then
			return 1
		fi

		if _contains "$response" "\"domainName\":\"$h\"" >/dev/null; then
			_domain_name=$(printf "%s" "$response" | jq -r '.domainName')
			_node=$(printf "%s" "$response" | jq -r '.node')
			if [ -z "$_node" ]; then
				_node="_acme-challenge"
			else
				_node="_acme-challenge.$_node"
			fi
			dnsId=$(printf "%s" "$response" | jq -r '.id')
			return 0
		fi
		p=$i
		i=$(_math "$i" + 1)
	done
	return 1
}

_get_recordid() {
	fulldomain=$1
	txtvalue=$2

	if ! _dynu_rest GET "dns/$dnsId/record"; then
		return 1
	fi

	if ! _contains "$response" "$txtvalue"; then
		_dns_record_id=0
		return 0
	fi

	_dns_record_id=$(printf "%s" "$response" | sed -e 's/[^{]*\({[^}]*}\)[^{]*/\1\n/g' | grep "\"textData\":\"$txtvalue\"" | sed -e 's/.*"id":\([^,]*\).*/\1/')
	return 0
}

_delete_txt_record() {
	_dns_record_id=$1

	if ! _dynu_rest DELETE "dns/$dnsId/record/$_dns_record_id"; then
		return 1
	fi

	if ! _contains "$response" "200"; then
		return 1
	fi

	return 0
}

_dynu_rest() {
	export _H1="Authorization: Bearer $Dynu_Token"
	export _H2="Content-Type: application/json"
	
	m=$1
	ep="$2"
	if [ $# -ge 3 ] && [ -n "$3" ]; then
		data="$3"
	elif [ "$m" = "DELETE" ]; then
		data=""
	fi
	
	if [[ ! -v data ]]; then
		response="$(_get "$Dynu_EndPoint/$ep")"
	else
		response="$(_post "$data" "$Dynu_EndPoint/$ep" "$m")"
	fi

	if [ "$?" != "0" ]; then
		bashio::log.error "error: $ep"
		return 1
	fi
	
	bashio::log.debug "response $response"
	return 0
}

_dynu_authentication() {
	realm="$(printf "%s" "$Dynu_ClientId:$Dynu_Secret" | _base64)"

	export _H1="Authorization: Basic $realm"
	export _H2="Content-Type: application/json"

	response="$(_get "$Dynu_EndPoint/oauth2/token")"
	if [ "$?" != "0" ]; then
		bashio::log.error "Authentication failed."
		return 1
	fi
	
	if _contains "$response" "Authentication Exception"; then
		bashio::log.error "Authentication failed."
		return 1
	fi
	
	if _contains "$response" "access_token"; then
		Dynu_Token=$(printf "%s" "$response" | jq -r '.access_token')
	fi
	
	if _contains "$Dynu_Token" "null"; then
		Dynu_Token=""
	fi

	bashio::log.debug "response $response"
	return 0
}

#a + b
_math() {
	_m_opts="$@"
	printf "%s" "$(($_m_opts))"
}

_contains() {
	_str="$1"
	_sub="$2"
	echo "$_str" | grep -- "$_sub" >/dev/null 2>&1
}

_base64() {
	openssl base64 -e | tr -d '\r\n'
}

# body  url [POST|PUT|DELETE]
_post() {
	body="$1"
	_post_url="$2"
	httpmethod="$3"

	if [ -z "$httpmethod" ]; then
		httpmethod="POST"
	fi
	
	if [ "$httpmethod" = "HEAD" ]; then
		_CURL="curl --silent -I  "
	else
		_CURL="curl --silent"
    fi
	
	if [ -z "$body" ]; then
		response="$($_CURL -X $httpmethod -H "$_H1" -H "$_H2" "$_post_url")"
	else
		response="$($_CURL -X $httpmethod -H "$_H1" -H "$_H2" --data "$body" "$_post_url")"
	fi
	
    ret=$?
    if [ "$ret" != "0" ]; then
		bashio::log.error "Please refer to https://curl.haxx.se/libcurl/c/libcurl-errors.html for error code: $ret"
    fi

	printf "%s" "$response"
	return $ret
}

# url getheader timeout
_get() {
	url="$1"
	
	curl --silent -H "$_H1" -H "$_H2" "$url"
    ret=$?
    if [ "$ret" != "0" ]; then
		bashio::log.error "Please refer to https://curl.haxx.se/libcurl/c/libcurl-errors.html for error code: $ret"
    fi

	return $ret
}

HANDLER="$1"; shift
if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge|deploy_cert)$ ]]; then
	"$HANDLER" "$@"
fi
