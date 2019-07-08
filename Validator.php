<?php
	declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * MIT License
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, June 2017
	 */

	namespace Opcenter\Dns\Providers\Cloudflare;

	use Cloudflare\API\Endpoints\User;
	use GuzzleHttp\Exception\ClientException;
	use Opcenter\Dns\Contracts\ServiceProvider;
	use Opcenter\Service\ConfigurationContext;

	class Validator implements ServiceProvider
	{
		/**
		 * Validate service value
		 *
		 * @param ConfigurationContext $ctx
		 * @param                      $var service value
		 * @return bool
		 */
		public function valid(ConfigurationContext $ctx, &$var): bool
		{
			if (!\is_array($var) || !isset($var['email'], $var['key'])) {
				return error("Cloudflare key must provide both email and key");
			}

			if (!ctype_xdigit($var['key'])) {
				return error("Key must be in hexadecimal");
			}
			if (!preg_match(\Regex::EMAIL, $var['email'])) {
				return error("Email address not properly formed");
			}

			foreach (['proxy', 'jumpstart'] as $name) {
				if (!isset($var[$name])) {
					// default
					$var[$name] = true;
				} else {
					if ($var[$name] === 1) {
						$var[$name] = true;
					} else if ($var[$name] === 0) {
						$var[$name] = false;
					}
					if (!\is_bool($var[$name])) {
						return error("`%s' must be true or false", $name);
					}
				}

			}

			if (!static::keyValid($var['email'], (string)$var['key'])) {
				return false;
			}

			return true;
		}

		public static function keyValid(string $email, string $key): bool
		{
			try {
				Api::api($email, $key, User::class)->getUserID();
			} catch (ClientException $e) {
				$response = \json_decode($e->getResponse()->getBody()->getContents(), true);
				$reason = array_get($response, 'errors.0.error_chain.0.message', "Invalid key");

				return error("CF key failed: %s", $reason);
			}

			return true;
		}

	}