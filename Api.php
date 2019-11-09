<?php declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * MIT License
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, August 2018
	 */

	namespace Opcenter\Dns\Providers\Cloudflare;

	use Cloudflare\API\Adapter\Guzzle;
	use Cloudflare\API\Auth\APIKey;
	use Cloudflare\API\Endpoints\API as CFAPI;
	use Opcenter\Dns\Providers\Cloudflare\Extensions\APIToken;

	class Api
	{

		/**
		 * Create a Cloudflare API instance
		 *
		 * @param string|null $email
		 * @param string $key
		 * @param string $abstract
		 * @return CFAPI
		 */
		public static function api(?string $email, string $key, string $abstract): CFAPI
		{
			if ($email && ctype_xdigit($key)) {
				// Master key
				$authHandler = new APIKey($email, $key);
			} else {
				// Scoped API token
				$authHandler = new APIToken($key);
			}
			$adapter = new Guzzle($authHandler);

			return new $abstract($adapter);
		}
	}