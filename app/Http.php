<?php
/**
 * Http - thin cURL wrapper used by every panel adapter.
 */

declare(strict_types=1);

class Http
{
    private string $baseUrl;
    private array $headers;
    private bool $verifyTls;
    private int $timeout;
    private ?array $basicAuth;
    private ?string $curlError = null;

    public function __construct(
        string $baseUrl,
        array $headers = [],
        bool $verifyTls = false,
        int $timeout = 90,
        ?array $basicAuth = null
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->headers = $headers;
        $this->verifyTls = $verifyTls;
        $this->timeout = $timeout;
        $this->basicAuth = $basicAuth;
    }

    public function baseUrl(): string
    {
        return $this->baseUrl;
    }

    public function lastError(): ?string
    {
        return $this->curlError;
    }

    /**
     * @return array{status:int,body:string,json:array|null,error:string}
     */
    public function request(string $path, string $method = 'GET', array $params = []): array
    {
        $url = $this->baseUrl . '/' . ltrim($path, '/');
        return $this->do($url, $method, $params);
    }

    public function absolute(string $url, string $method = 'GET', array $params = []): array
    {
        return $this->do($url, $method, $params);
    }

    private function do(string $url, string $method, array $params): array
    {
        $this->curlError = null;
        $ch = curl_init();

        $headers = $this->headers;
        $isPost = strtoupper($method) === 'POST';
        if ($isPost) {
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params, '', '&', PHP_QUERY_RFC3986));
        } elseif ($params) {
            $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
        }

        $opts = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_SSL_VERIFYPEER => $this->verifyTls,
            CURLOPT_SSL_VERIFYHOST => $this->verifyTls ? 2 : 0,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => min(20, $this->timeout),
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT => 'OLSpanel-Account-Migrator/1.0',
        ];
        if ($this->basicAuth !== null) {
            $opts[CURLOPT_USERPWD] = $this->basicAuth[0] . ':' . $this->basicAuth[1];
            $opts[CURLOPT_HTTPAUTH] = CURLAUTH_BASIC;
        }

        curl_setopt_array($ch, $opts);

        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($errno) {
            $this->curlError = $error;
            return ['status' => 0, 'body' => '', 'json' => null, 'error' => $error];
        }

        $body = (string)$body;
        $json = null;
        if ($body !== '') {
            $decoded = json_decode($body, true);
            if (is_array($decoded)) {
                $json = $decoded;
            }
        }

        return ['status' => $status, 'body' => $body, 'json' => $json, 'error' => ''];
    }
}