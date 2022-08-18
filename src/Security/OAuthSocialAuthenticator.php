<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Security\Exception\NotVerifiedEmailException;
use Doctrine\ORM\NonUniqueResultException;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Client\Provider\FacebookClient;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use KnpU\OAuth2ClientBundle\Client\Provider\GoogleClient;
use KnpU\OAuth2ClientBundle\Client\Provider\InstagramClient;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use League\OAuth2\Client\Provider\FacebookUser;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Provider\InstagramResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class OAuthSocialAuthenticator extends SocialAuthenticator
{

    use TargetPathTrait;

    private  $router;
    private  $clientRegistry;
    private  $userRepository;
    private  $requestStack;

    /**
     * @param RouterInterface $router
     * @param ClientRegistry $clientRegistry
     * @param UserRepository $userRepository
     * @param RequestStack $requestStack
     */
    public function __construct(
        RouterInterface $router,
        ClientRegistry  $clientRegistry,
        UserRepository  $userRepository,
        RequestStack    $requestStack
    )
    {
        $this->router = $router;
        $this->clientRegistry = $clientRegistry;
        $this->userRepository = $userRepository;
        $this->requestStack = $requestStack;
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
        return 'oauth_check' === $request->attributes->get('_route');
    }

    /**
     * @param Request $request
     * @return AccessToken
     */
    public function getCredentials(Request $request): AccessToken
    {
        return $this->fetchAccessToken($this->getClient($request));
    }

    /**
     * @param $credentials
     * @param UserProviderInterface $userProvider
     * @return User|UserInterface|null
     * @throws NonUniqueResultException
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        /** @var Request $request */
        $request = $this->requestStack->getCurrentRequest();

        /** @var FacebookUser|GithubResourceOwner|GoogleUser|InstagramResourceOwner $socialUser */
        $socialUser = $this->getClient($request)->fetchUserFromToken($credentials);

        if (method_exists($socialUser, 'getNickName')) {
            if ($socialUser->getNickname() === null) {
                throw new NotVerifiedEmailException();
            }
        } else {
            if ($socialUser->getEmail() === null) {
                throw new NotVerifiedEmailException();
            }
        }

        return $this->userRepository->findOrCreateFromOauth($socialUser, $request->get('service'));
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
        return new RedirectResponse($targetPath ?: '/');
    }

    /**
     * @param Request $request
     * @return OAuth2ClientInterface
     */
    public function getClient(Request $request): OAuth2ClientInterface
    {
        $service = $request->get('service');
        return $this->clientRegistry->getClient($service);
    }
}


//
//namespace App\Security;
//
//use App\Repository\UserRepository;
//use App\Security\Exception\NotVerifiedEmailException;
//use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
//use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
//use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
//use League\OAuth2\Client\Provider\GithubResourceOwner;
//use League\OAuth2\Client\Token\AccessToken;
//use Symfony\Component\HttpClient\HttpClient;
//use Symfony\Component\HttpFoundation\RedirectResponse;
//use Symfony\Component\HttpFoundation\Request;
//use Symfony\Component\Routing\RouterInterface;
//use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
//use Symfony\Component\Security\Core\Exception\AuthenticationException;
//use Symfony\Component\Security\Core\Security;
//use Symfony\Component\Security\Core\User\UserProviderInterface;
//use Symfony\Component\Security\Http\Util\TargetPathTrait;
//
//class OAuthSocialAuthenticator extends SocialAuthenticator
//{
//
//    use TargetPathTrait;
//
//    /**
//     * @var RouterInterface
//     */
//    protected $router;
//    /**
//     * @var ClientRegistry
//     */
//    protected $clientRegistry;
//    /**
//     * @var UserRepository
//     */
//    protected $userRepository;
//
//    public function __construct(RouterInterface $router, ClientRegistry $clientRegistry, UserRepository $userRepository)
//    {
//        $this->router = $router;
//        $this->clientRegistry = $clientRegistry;
//        $this->userRepository = $userRepository;
//    }
//
//    public function start(Request $request, AuthenticationException $authException = null): RedirectResponse
//    {
//        return new RedirectResponse($this->router->generate('app_login'));
//    }
//
//    public function supports(Request $request): bool
//    {
//        return 'oauth_check' === $request->attributes->get('_route') && $request->get('service') === 'github';
//    }
//
//    public function getCredentials(Request $request)
//    {
//        return $this->fetchAccessToken($this->getClient());
//    }
//
//    /**
//     * @param AccessToken $credentials
//     */
//    public function getUser($credentials, UserProviderInterface $userProvider)
//    {
//        $githubUser = $this->getClient()->fetchUserFromToken($credentials);
//
//        //On recupère l'émail de l'utilisateur
//        $response = HttpClient::create()->request(
//            'GET',
//            'https://api.github.com/user/emails',
//            [
//                'headers' => [
//                    'authorization' => "token {$credentials->getToken()}"
//                ]
//            ]
//        );
//
//        $emails = json_decode($response->getContent(), true);
//        foreach ($emails as $email){
//            //retransformé githuUser avec mail déjà recuperer
//            if ($email['primary'] === true && $email['verified'] === true){
//                $data = $githubUser->toArray();
//                $data['email'] = $email['email'];
//                $githubUser = new GithubResourceOwner($data);
//            }
//        }
//
//        if ($githubUser->getEmail() === null){
//            throw new NotVerifiedEmailException();
//        }
//
//        return $this->userRepository->findOrCreateFromGithubOauth($githubUser);
//
//    }
//
//    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): RedirectResponse
//    {
//        if ($request->hasSession()){
//            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
//        }
//
//        return new RedirectResponse($this->router->generate('app_login'));
//    }
//
//    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey): RedirectResponse
//    {
//        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);
//
//        return new RedirectResponse($targetPath ?: '/');
//    }
//
//    public function getClient():GithubClient
//    {
//        return $this->clientRegistry->getClient('github');
//    }
//}