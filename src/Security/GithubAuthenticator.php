<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Security\Exception\NotVerifiedEmailException;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\NoResultException;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;

class GithubAuthenticator extends SocialAuthenticator
{
    use TargetPathTrait;

    private RouterInterface $router;
    private ClientRegistry $clientRegistry;
    private UserRepository $userRepository;

    /**
     * @param RouterInterface $router
     * @param ClientRegistry $clientRegistry
     * @param UserRepository $userRepository
     */
    public function __construct(RouterInterface $router, ClientRegistry $clientRegistry, UserRepository $userRepository)
    {
        $this->router = $router;
        $this->clientRegistry = $clientRegistry;
        $this->userRepository = $userRepository;
    }

    /**
     * @param Request $request
     * @param AuthenticationException|null $authException
     * @return RedirectResponse
     */
    public function start(Request $request, AuthenticationException $authException = null): RedirectResponse
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    /**
     * @param Request $request
     * @return bool
     */
    public function supports(Request $request): bool
    {
        return 'oauth_check' === $request->attributes->get('_route') && $request->get('service') === 'github';
    }

    /**
     * @param Request $request
     * @return AccessToken
     */
    public function getCredentials(Request $request): AccessToken
    {
        return $this->fetchAccessToken($this->getClient());
    }

    /**
     * @param AccessToken $credentials
     * @param UserProviderInterface $userProvider
     * @return User
     * @throws NonUniqueResultException
     * @throws ClientExceptionInterface
     * @throws RedirectionExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function getUser($credentials, UserProviderInterface $userProvider): User
    {
        /** @var GithubResourceOwner $githubUser */
        $githubUser = $this->getClient()->fetchUserFromToken($credentials);

        // On récupère l'email de l'utilisateur
        $response = HttpClient::create()->request(
            'GET',
            'https://api.github.com/user/emails',
            [
                'headers' => [
                    'authorization' => "token {$credentials->getToken()}"
                ]
            ]
        );

        $emails = json_decode($response->getContent(), true);
        foreach ($emails as $email) {
            if ($email['primary'] === true && $email['verified'] === true){
                $data = $githubUser->toArray();
                $data['email'] = $email['email'];
                $githubUser = new GithubResourceOwner($data);
            }
        }

        if ($githubUser->getEmail() === null){
            throw new NotVerifiedEmailException();
        }

        return $this->userRepository->findOrCreateFromGithubOauth($githubUser);
    }

    /**
     * @param Request $request
     * @param AuthenticationException $exception
     * @return RedirectResponse
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): RedirectResponse
    {
        if ($request->hasSession()) {
            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
        }

        return new RedirectResponse($this->router->generate('app_login'));
    }

    /**
     * @param Request $request
     * @param TokenInterface $token
     * @param string $providerKey
     * @return RedirectResponse
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey): RedirectResponse
    {
        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);
        return new RedirectResponse($targetPath ?: $this->router->generate('home'));
    }

    /**
     * @return GithubClient|OAuth2ClientInterface
     */
    public function getClient(): GithubClient
    {
        return $this->clientRegistry->getClient('github');
    }
}