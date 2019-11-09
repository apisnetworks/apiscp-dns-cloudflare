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
	 * Written by Matt Saladna <matt@apisnetworks.com>, November 2019
	 */

	namespace Opcenter\Dns\Providers\Cloudflare\Extensions;

	use Cloudflare\API\Auth\Auth;

	class APIToken implements Auth
	{
		private $apiToken;

		public function __construct(string $apiToken)
		{
			$this->apiToken = $apiToken;
		}

		public function getHeaders(): array
		{
			return [
				'Authorization' => 'Bearer ' . $this->apiToken
			];
		}
	}