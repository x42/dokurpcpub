<?php
/**
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Robin Gareus <robin@gareus.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class action_plugin_rpcpub extends DokuWiki_Action_Plugin {

    /**
     * return some info
     */
    function getInfo(){
        return array(
            'author' => 'Robin Gareus',
            'email'  => 'robin@gareus.org',
            'date'   => '2008-10-23',
            'name'   => 'rpcpub',
            'desc'   => 'Publish Changes via wikixmlrpc2',
            'url'    => 'http://mir.dnsalias.com/wiki/dokurpcpub',
        );
    }

    /**
     * register the eventhandlers
     */
    function register(&$contr){
        $contr->register_hook('IO_WIKIPAGE_WRITE',
                              'AFTER',
                              $this,
                              'handle_wikipage_write',
                               array());

        #TODO publish on MEDIA_UPLOAD_FINISH 
        #TODO IO_NAMESPACE_CREATED & IO_NAMESPACE_DELETED
        #TODO: also hook into page-lock & drafts
        # publish: busy/locked.
        # HTML_EDITFORM_OUTPUT, HTML_DRAFTFORM_OUTPUT, HTML_CONFLICTFORM_OUTPUT
        #

    }

    /**
     * called when(after) writing a new page to disk.
     * publishing is triggered from here.
     * see http://www.dokuwiki.org/devel:events_list#io_wikipage_write
     */
    function handle_wikipage_write(&$event, $param){
        global $ID;
        if  (!$this->getConf('enable publishing')) return; 

        // if an old revision is safed -> run away
        if ($event->data[3]) return true;

        $ns=$event->data[1];
        $name=$event->data[2];
        #$path=$event->data[0][0];
        if (empty($event->data[0][1])) {
            ; //page has been deleted
        }

        if ($ID != $ns.(!empty($ns)?':':'').$name) {
            msg('rpcpub: not publishing wiki-page other than current page ID="'.$ID.'" <> file="'.$ns.':'.$name.'"');
            $this->_debug('rpcpub: not publishing wiki-page other than current page ID="'.$ID.'" <> file="'.$ns.':'.$name.'"');
            # Note: this prevents publish loops, the XML-RPC does not set $ID.
            return true;
        }

        # check if anonymous users can READ this before publishing.
        #if(auth_quickaclcheck($ID) < AUTH_EDIT || auth_aclcheck($ID, '', array()) < AUTH_READ){
        #    return true;
        #}

        if(isHiddenPage($ID)){
            return true;
        }

        $meta=p_get_metadata($ID);
        # skip '~~DRAFT~~' - requires the blog plugin.
        if ($meta['type'] == 'draft'){
            return true;
        }
        # TODO: check for other meta-data, namespace-blacklist, etc.

        # TODO: prevent publish loops.

        $this->_wikiRpcPublish($ID);
        return true;
    }

    private function _wikiRpcPublish($id){

        # get page contents
        $content = rawWiki($id,'');
        #$meta = p_get_metadata($id);

        //TODO: allow to rewrite, prepend namespace, regexp replace, etc
        $id=$this->getConf('target_ns').$id;
 
        # format a XMP-RPC message to update the page
        $req = xmlrpc_encode_request("wiki.putPage", array($id, $content, "pub", false));

        $errors=0;
        # TODO: loop over mult. servers to update {
            $o=array('doku_host' => $this->getConf('target_host'),
                     'doku_base' => $this->getConf('target_path'),
                     'http_port' => $this->getConf('target_port'),
                     'protocol'  => $this->getConf('target_proto'),
                    );

            #call "curl ... &" -> fire and forget 
            #OR use make request here and inform user about result(s).
            $rv=$this->dokuXmlRpc($req, $o);

            #$this->_debug('parsed RPC reply: '.print_r($rv,true));
            if ($rv!="0") {
                $errors++; // TODO queue error message.
                $this->_debug(" !!! XMLRPC error #$errors");
            }
        # }

        return true;
    }


    /* Doku RPC client */ /*{{{*/ 
    /**
     * contact another dokuwiki via XML-RPC
     * adds authentication-tokens is available.
     * @TODO use inc/HTTPClient.php
     */
    private function dokuXmlRpc($request, $o) {/*{{{*/
        $req_authorized=false;

        $this->_debug("RGX". print_r($o,true));

        $host=$o['doku_host'];
        $path=$o['doku_base'].'/lib/exe/xmlrpc.php';
        $port=$o['http_port'] || "80";
        $transport= strncasecmp($o['protocol'],"HTTPS",5)?'':'ssl://'; 
        $proto= empty($transport)?'http://':'https://'; 

        $this->_debug("RGX :: $proto$host$path");

        if (1 && ($oa = &plugin_load('helper', 'oauth'))){
            #  check if we have an oauth-key or other credentials -> add them
            $oauth_keys=$oa->oauthLookup($proto,$host,$path);  // TODO use - $this->getConf(..)

            if (is_array($oauth_keys)) {
                $path=$oa->oauthSign($oauth_keys, $proto.$host.$path, NULL, "POST"); 
                $path=substr($path,strlen($proto)); # remove protocol 
                if (!strpos($path,'/')) { 
                    # should never happen! empty paths are normalized to '/' for the oAuth base-url
                    $path=$o['doku_base']; 
                    $this->_debug("OAUTHSIGN returned empty path!");
                } else { 
                    $path=substr($path,strpos($path,'/')); # remove hostname (and port) 
                }
                $this->_debug("OAUTHSIGNED path&query-params: $path");
                $req_authorized=true;
            }
        }

        if (0 && !$req_authorized) { // only for HTTPS?!
            $path.='?';
            if ($o['dw_user']) $path.='user='.urlencode($o['dw_user']).'&'; # rawurlencode ?!
            if ($o['dw_pass']) $path.='pass='.urlencode($o['dw_pass']).'&';
            $path=preg_replace('![?&]$!', '', $path);
        }

        $x = $this->httpPost($o['doku_host'], $path, $request, $transport, $port);

        #$this->_debug("XMLRPC response: $x");
        #$this->_debug("----");

        return $this->parseXmlRpcResponse($x);
    }/*}}}*/

    /**
     * wrapper around xmlrpc_decode()
     */
    private function parseXmlRpcResponse($x) {/*{{{*/
      if (empty($x)) return NULL;
      $response = xmlrpc_decode($x);
      if (xmlrpc_is_fault($response)) {
        $this->_debug("xmlrpc: $response[faultString] ($response[faultCode])");
        msg("xmlrpc: $response[faultString] ($response[faultCode])",-1); // XXX
        return NULL;
      } 
      return($response);
    }/*}}}*/
    /*}}}*/

    /* HTTP client - TODO replace with inc/HTTPClient.php */ /*{{{*/ 
    /**
     * HTTP[s] POST request
     *
     * @author Robin Gareus <robin@gareus.org>
     * @param $host: hostname ; eg 'example.org'
     * @param $path: request' eg '/index.php?id=123'
     * @param $data_to_send : data to POST after the HTTP header.
     * @param $opts various transport layer options (ssl, port, cert,..)
     * @param $auth optional username, password and type ('basic', 'nodigest')
     * @param $head custom http header
     *
     * if $opts is an empty array() a standard HTTP to port 80 request is performed.
     *
     * set auth['type']='basic' to use plain-text auth,
     * digest-auth will be handled automatically if $auth['username'] is set and a 401
     * status is encountered. - use auth['type']='nodigest' to override.
     *
     */
    function httpPost($host, $path, $data_to_send, /*{{{*/
                      $opts=array('cert'=>"", 'transport' =>'ssl://', 'port'=>443, 'headers'=>0),
                      $auth=array('username'=>"", 'password'=>"", 'type'=>""),
                      $head=array('Content-type' =>'text/xml')
                     ){
        $transport=''; $port=80;
        if (!empty($opts['transport'])) $transport=$opts['transport'];
        if (!empty($opts['port'])) $port=$opts['port'];
        $remote=$transport.$host.':'.$port;

        $context = stream_context_create();
        $result = stream_context_set_option($context, 'ssl', 'verify_host', true);
        if (!empty($opts['cert'])) {
            $result = stream_context_set_option($context, 'ssl', 'cafile', $opts['cert']);
            $result = stream_context_set_option($context, 'ssl', 'verify_peer', true);
        }else{
            $result = stream_context_set_option($context, 'ssl', 'allow_self_signed', true);
        }
        $fp = stream_socket_client($remote, $err, $errstr, 60, STREAM_CLIENT_CONNECT, $context);

        if (!$fp) {
            trigger_error('httpPost error: '.$errstr);
            return NULL;
        }

        $req='';
        $req.="POST $path HTTP/1.1\r\n";
        $req.="Host: $host\r\n";
        if ($auth['type']=='basic' && !empty($auth['username'])) {
            $req.="Authorization: Basic ";
            $req.=base64_encode($auth['username'].':'.$auth['password'])."\r\n";
        }
        elseif ($auth['type']=='digest' && !empty($auth['username'])) {
            $req.='Authorization: Digest ';
            foreach ($auth as $k => $v) {
            if (empty($k) || empty($v)) continue;
            if ($k=='password') continue;
            $req.=$k.'="'.$v.'", ';
        }
            $req.="\r\n";
        }

        foreach ($head as $k => $v) {
            $req.=$k.': '.$v."\r\n";
        }
        if (empty($head['Content-type'])) {
            $ct='text/xml';
            $req.="Content-type: $ct\r\n";
        }

        $req.='Content-length: '. strlen($data_to_send) ."\r\n";
        $req.="Connection: close\r\n\r\n";

        fputs($fp, $req);
        fputs($fp, $data_to_send);

        while(!feof($fp)) { $res .= fgets($fp, 128); }
        fclose($fp);

        if ($auth['type']!='nodigest'
                && !empty($auth['username'])
                && $auth['type']!='digest' # prev. digest AUTH failed.
                && preg_match("/^HTTP\/[0-9\.]* 401 /", $res)) {
            if (1 == preg_match("/WWW-Authenticate: Digest ([^\n\r]*)\r\n/Us", $res, $matches)) {
                foreach (split(",", $matches[1]) as $i) {
                    $ii=split("=",trim($i),2);
                    if (!empty($ii[1]) && !empty($ii[0])) {
                        $auth[$ii[0]]=preg_replace("/^\"/",'', preg_replace("/\"$/",'', $ii[1]));
                    }
                }
                $auth['type']='digest';
                $auth['uri']='https://'.$host.$path;
                $auth['cnonce']=$this->_randomNonce();
                $auth['nc']=1;
                $a1=md5($auth['username'].':'.$auth['realm'].':'.$auth['password']);
                $a2=md5('POST'.':'.$auth['uri']);
                $auth['response']=md5($a1.':'.$auth['nonce'].':'.$auth['nc'].':'.$auth['cnonce'].':'.$auth['qop'].':'.$a2);
                return httpPost($host, $path, $data_to_send, $opts, $auth, $head);
            }
        } # end if DIGEST AUTH

        if (1 != preg_match("/^HTTP\/[0-9\.]* ([0-9]{3}) ([^\r\n]*)/", $res, $matches)) {
            trigger_error('httpPost: invalid HTTP reply.');
            return NULL;
        }

        if (1 != preg_match("/^2[0-9]{2}$/", $matches[1])) {
            trigger_error('httpPost: HTTP error: '.$matches[1].' '.$matches[2]);
            return NULL;
        }

        if (!$opts['headers']) {
            $res=preg_replace("/^.*\r\n\r\n/Us",'',$res);
        }

        return $res;
    }/*}}}*/

    /**
     * generate a random string
     *
     * @param len length of the returned string, <1 uses a random length between 6 and 15 chars
     * @return random string
     */
    private function _randomNonce($len=0, $rand=0) {/*{{{*/
        srand(microtime()*hexdec(substr(md5($rand),6,6)));
        $chars = "ABCDEFGHIJKMNOPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz023456789";
        $i=0; $rv='';
        if ($len < 1) $len= (6+rand()%10);
        while ($i++ < $len) {
        $rv.=$chars[rand() % strlen($chars)];
        }
        return $rv;
    }/*}}}*/

    /*}}}*/

    private function _debug ($m = null){/*{{{*/
        $PSdebug= true; //XXX
        $PSlogfile= '/tmp/RpcPub.debug';
        if (! isset($PSdebug) || $PSdebug === false) return;

        if (! is_writable(dirname($PSlogfile)) &! is_writable($PSlogfile)){
            header("HTTP/1.1 500 Internal Server Error");
            echo 'Cannot write to debug log: ' . $PSlogfile;
            return;
        }
        $vhost=DOKU_URL;
        error_log($vhost.' '.date("c ").$m."\n", 3, $PSlogfile);
    } /*}}}*/

}
/* vim: set ts=4 sw=4 et foldmethod=marker enc=utf-8 : */

