<?php

namespace Whitehatsllc\LumenPassportMongodb\Http\Controllers;

use Whitehatsllc\PassportMongodb\Passport;
use Whitehatsllc\PassportMongodb\Token;
use Whitehatsllc\PassportMongodb\Client;
use Zend\Diactoros\Response as Psr7Response;
use Psr\Http\Message\ServerRequestInterface;
use Whitehatsllc\LumenPassportMongodb\LumenPassport;

/**
 * Class AccessTokenController
 * @package Whitehatsllc\LumenPassportMongodb\Http\Controllers
 */
class AccessTokenController extends \Whitehatsllc\PassportMongodb\Http\Controllers\AccessTokenController
{

    /**
     * Authorize a client to access the user's account.
     *
     * @param  ServerRequestInterface  $request
     * @return Response
     */
    public function issueToken(ServerRequestInterface $request) {

        $response = $this->withErrorHandling(function () use ($request) {
            $input = (array) $request->getParsedBody();
            $clientId = isset($input['client_id']) ? $input['client_id'] : null;

            // Overwrite password grant at the last minute to add support for customized TTLs
            $this->server->enableGrantType(
                    $this->makePasswordGrant(), LumenPassport::tokensExpireIn(null, $clientId)
            );

            return $this->server->respondToAccessTokenRequest($request, new Psr7Response);
        });

        if ($response->getStatusCode() < 200 || $response->getStatusCode() > 299) {
            return $response;
        }

        $payload = json_decode($response->getBody()->__toString(), true);

        if (isset($payload['access_token'])) {
            $tokenId = $this->jwt->parse($payload['access_token'])->getClaim('jti');
            $token = $this->tokens->getTokenById($tokenId);
            //Check if the Client is first party
            if ((new Client)->isFirstParty($token['client_id']) && LumenPassport::$allowMultipleTokens) {
                // We keep previous tokens for password clients
            } else {
                $this->revokeOrDeleteAccessTokens($token, $tokenId);
            }
        }

        return $response;
    }

    /**
     * Create and configure a Password grant instance.
     *
     * @return \League\OAuth2\Server\Grant\PasswordGrant
     */
    private function makePasswordGrant() {
        $grant = new \League\OAuth2\Server\Grant\PasswordGrant(
                app()->make(\Laravel\Passport\Bridge\UserRepository::class), app()->make(\Laravel\Passport\Bridge\RefreshTokenRepository::class)
        );

        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());

        return $grant;
    }

    /**
     * Revoke the user's other access tokens for the client.
     *
     * @param  Token $token
     * @param  string $tokenId
     * @return void
     */
    protected function revokeOrDeleteAccessTokens($token, $tokenId) {
        $query = Token::where('user_id', $token['user_id'])->where('client_id', $token['client_id']);
        if ($tokenId) {
            $query->where('id', '<>', $tokenId);
        }
        if (Passport::$pruneRevokedTokens) {
            $query->delete();
        } else {
            $query->update(['revoked' => true]);
        }
    }

}
