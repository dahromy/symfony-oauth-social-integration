<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\Provider\FacebookClient;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use KnpU\OAuth2ClientBundle\Client\Provider\GoogleClient;
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
     * @param ClientRegistry $clientRegistry
     * @return RedirectResponse
     * @Route("/connect/github", name="github_connect")
     */
    public function connectGithub(ClientRegistry $clientRegistry): RedirectResponse
    {
        /** @var GithubClient $client */
        $client = $clientRegistry->getClient('github');
        return $client->redirect(['read:user', 'user:email']);
    }

    /**
     * @param ClientRegistry $clientRegistry
     * @return RedirectResponse
     * @Route("/connect/facebook", name="facebook_connect")
     */
    public function connectFacebook(ClientRegistry $clientRegistry): RedirectResponse
    {
        /** @var FacebookClient $client */
        $client = $clientRegistry->getClient('facebook');
        return $client->redirect(['public_profile', 'email']);
    }

    /**
     * @param ClientRegistry $clientRegistry
     * @return RedirectResponse
     * @Route("/connect/google", name="google_connect")
     */
    public function connectGoogle(ClientRegistry $clientRegistry): RedirectResponse
    {
        /** @var GoogleClient $client */
        $client = $clientRegistry->getClient('google');
        return $client->redirect([
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'openid'
        ]);
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
