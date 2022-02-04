<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\Provider\FacebookClient;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use KnpU\OAuth2ClientBundle\Client\Provider\GoogleClient;
use KnpU\OAuth2ClientBundle\Client\Provider\InstagramClient;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    /**
     * @Route("/login", name="app_login")
     */
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // if ($this->getUser()) {
        //     return $this->redirectToRoute('target_path');
        // }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    /**
     * @param $service
     * @param ClientRegistry $clientRegistry
     * @return RedirectResponse
     * @Route("/connect/{service}", name="social_connect")
     */
    public function connect($service, ClientRegistry $clientRegistry): RedirectResponse
    {
        /** @var InstagramClient|FacebookClient|GoogleClient|GithubClient $client */
        $client = $clientRegistry->getClient($service);
        return $client->redirect($this->getScopesFromService($service));
    }

    /**
     * @param string $service
     * @return array|string[]
     */
    public function getScopesFromService(string $service): array
    {
        $scopes = [];
        switch ($service){
            case 'github':
                $scopes = ['read:user', 'user:email'];
                break;
            case 'google':
                $scopes = [
                    'https://www.googleapis.com/auth/userinfo.email',
                    'https://www.googleapis.com/auth/userinfo.profile',
                    'openid'
                ];
                break;
            case 'facebook':
                $scopes = ['public_profile', 'email'];
                break;
            case 'instagram':
                $scopes = ['user_profile', 'user_media'];
                break;
            default:
                break;
        }

        return $scopes;
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
