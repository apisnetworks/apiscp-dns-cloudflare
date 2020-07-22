<?php declare(strict_types=1);
/**
 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
 *
 * Unauthorized copying of this file, via any medium, is
 * strictly prohibited without consent. Any dissemination of
 * material herein is prohibited.
 *
 * For licensing inquiries email <licensing@apisnetworks.com>
 *
 * Written by Matt Saladna <matt@apisnetworks.com>, April 2020
 */


	namespace Opcenter\Dns\Providers\Cloudflare\Extensions;

	use Cloudflare\API\Adapter\Guzzle;
	use Cloudflare\API\Adapter\JSONException;
	use Cloudflare\API\Adapter\ResponseException;
	use Cloudflare\API\Auth\Auth;
	use GuzzleHttp\Client;
	use GuzzleHttp\Exception\ConnectException;
	use Psr\Http\Message\ResponseInterface;

	class GuzzleAdapter extends Guzzle
	{
		const CONNECTION_TIMEOUT = 5;

		protected $client;

		public function __construct(Auth $auth, string $baseURI = null)
		{
			if ($baseURI === null) {
				$baseURI = 'https://api.cloudflare.com/client/v4/';
			}

			$headers = $auth->getHeaders();

			$this->client = new Client([
				'base_uri' => $baseURI,
				'headers'  => $headers,
				'Accept'   => 'application/json',
				'connect_timeout'  => self::CONNECTION_TIMEOUT
			]);
		}

		public function request(string $method, string $uri, array $data = [], array $headers = [])
		{
			if (!\in_array($method, ['get', 'post', 'put', 'patch', 'delete'])) {
				throw new \InvalidArgumentException('Request method must be get, post, put, patch, or delete');
			}

			try {
				$response = $this->client->$method($uri, [
					'headers'                              => $headers,
					($method === 'get' ? 'query' : 'json') => $data,
				]);
			} catch (ConnectException $e) {
				$ctx = $e->getHandlerContext();
				if (array_get($ctx, 'total_time', 999) > self::CONNECTION_TIMEOUT - 1) {
					throw new ConnectException(
						_("Unable to connect to Cloudflare's API after " .
							self::CONNECTION_TIMEOUT . ' second timeout. ' .
							'See https://cloudflarestatus.com for more details.'),
						$e->getRequest()
					);
				}
				throw $e;
			}

			$this->checkError($response);

			return $response;
		}

		protected function checkError(ResponseInterface $response)
		{
			$json = json_decode((string)$response->getBody());

			if (json_last_error() !== JSON_ERROR_NONE) {
				throw new JSONException();
			}

			if (isset($json->errors) && \count($json->errors) >= 1) {
				throw new ResponseException($json->errors[0]->message, $json->errors[0]->code);
			}

			if (isset($json->success) && !$json->success) {
				throw new ResponseException('Request was unsuccessful.');
			}
		}
	}