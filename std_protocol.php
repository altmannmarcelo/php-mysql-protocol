<?php 
class m_connection
{
    private $user;
    private $password;
    private $host;
    private $port;
    private $socket;
    public function __construct($user,$password, $host, $port)
    {
        $this->user = $user;
        $this->password = $password;
        $this->host =$host;
        $this->port = $port;
        $this->socket = fsockopen($host, $port, $errno, $errstr, 30);
        //echo "started\n";
    }
    
    public function start()
    {
        if($this->socket)
        {
            $length_b1 = bin2hex(fread($this->socket, 1));
            $length_b2 = bin2hex(fread($this->socket, 1));
            $length_b3 = bin2hex(fread($this->socket, 1));
            $length = $length_b1;
            if ($length_b2 != '00')
                $length .= $length_b2;
                
            if ($length_b3 != '00')
                $length .= $length_b3;
                
            $length_dec = base_convert($length, 16, 10);
            echo 'payload_length: ' . $length . " ($length_dec)\n" ;
            
            $seq = bin2hex(fread($this->socket, 1));
            echo 'sequence_id: ' . $seq . "\n";
            
            
            $payload_command = bin2hex(fread($this->socket, 1));
            $length_dec--;
            switch($payload_command)
            {
                case "0a":
                    echo "Initial Handshake Packet\n";
                    $this->readProtocolHandshakeV10($length_dec);
                    break;
                default:
                    echo "unkonw command\n";
            }
        }
    }
    private function readProtocolHandshakeV10($length_dec)
    {
        $payload;
        for($i=$length_dec;$i>0;$i--)
        {
            $payload[]=bin2hex(fread($this->socket, 1));
        }
        
        $server_version;
        while($payload[0] != '00')
        {
            $server_version .= $payload[0];
            array_shift($payload);
        }
        array_shift($payload);
        echo "Server Version: " . hex2bin($server_version) . "\n";
        $connection_id;
        echo 'Connection ID HEX: ' . $payload[0] . $payload[1] . $payload[2] . $payload[3] . "\n";
        for($i=0;$i<4;$i++)
        {
            if($payload[0] != '00')
                $connection_id .= $payload[0];
                
            array_shift($payload);
        }
        echo "Connection ID: " . base_convert($connection_id, 16, 10) . "\n";
        $auth_plugin_data_part_1;
        for($i=0;$i<8;$i++)
        {
            if($payload[0] != '00')
                $auth_plugin_data_part_1 .= $payload[0];
                
            array_shift($payload);
        }
        echo "auth_plugin_data_part_1: " . hex2bin($auth_plugin_data_part_1) . "\n";
        
        //filler_1 (1) -- 0x00
        array_shift($payload);
        
        //capability_flag_1 (2) 
        array_shift($payload);
        array_shift($payload);
        
        //character_set (1)
        array_shift($payload);
        
        //status_flags (2) 
        array_shift($payload);
        array_shift($payload);
        
        //capability_flags_2 (2)
        array_shift($payload);
        array_shift($payload);
        
        $length_auth_plugin_data = $payload[0];
        array_shift($payload);
        echo "length_auth_plugin_data: " . base_convert($length_auth_plugin_data, 16, 10) . "\n";
        
        //string[10]     reserved (all [00])
        array_shift($payload);
        array_shift($payload);
        array_shift($payload);
        array_shift($payload);
        array_shift($payload);
        array_shift($payload);
        array_shift($payload);
        array_shift($payload);
        array_shift($payload);
        
        array_shift($payload);
        $length_auth_plugin_data_dec=(base_convert($length_auth_plugin_data, 16, 10) - strlen(hex2bin($auth_plugin_data_part_1))) . "\n";
        for($i=0;$i<$length_auth_plugin_data_dec;$i++)
        {
            if($payload[0] != '00')
                $auth_plugin_data_part_1 .= $payload[0];
                
            array_shift($payload);
        }
        echo "auth_plugin_data_part_1: " . hex2bin($auth_plugin_data_part_1) . "\n";
        $auth_method;
        while(count($payload) > 0)
        {
            if($payload[0] != '00')
                $auth_method .= $payload[0];
                
            array_shift($payload);
        }
        echo "auth_method: " . hex2bin($auth_method) . "\n";
        
        echo "hash from MySQL: *14E65567ABDB5135D0CFD9A70B3032C179A49EE7\n";
        //SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat> SHA1( SHA1( password ) ) )
        //echo "my hash:" . $this->xor_string(sha1('secret'),sha1(hex2bin($auth_plugin_data_part_1) . sha1(sha1('secret')))) . "\n"; 
        echo "my hash:         *" . mb_strtoupper(sha1(hex2bin(sha1('secret')))) . "\n";
    }
    
    private function xor_string($string, $key) {
    $str_len = strlen($string);
    $key_len = strlen($key);

    for($i = 0; $i < $str_len; $i++) {
        $string[$i] = $string[$i] ^ $key[$i % $key_len];
    }

    return $string;
}
}
$host = '127.0.0.1';
$port = 3307;

$connection = new m_connection('root', 'secret', $host, $port);
$connection->start();
?>
