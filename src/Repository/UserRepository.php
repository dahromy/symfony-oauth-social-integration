<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\Persistence\ManagerRegistry;
use League\OAuth2\Client\Provider\FacebookUser;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Provider\InstagramResourceOwner;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @method User|null find($id, $lockMode = null, $lockVersion = null)
 * @method User|null findOneBy(array $criteria, array $orderBy = null)
 * @method User[]    findAll()
 * @method User[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function upgradePassword(UserInterface $user, string $newHashedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        $user->setPassword($newHashedPassword);
        $this->_em->persist($user);
        $this->_em->flush();
    }

    /**
     * @param GithubResourceOwner $owner
     * @return User
     * @throws NonUniqueResultException
     */
    public function findOrCreateFromGithubOauth(GithubResourceOwner $owner): User
    {
        $em = $this->getEntityManager();

        /** @var User|null $user */
        $user = $this->createQueryBuilder('u')
            ->where('u.githubId = :githubId')
            ->orWhere('u.email = :email')
            ->setParameters([
                'githubId' => $owner->getId(),
                'email' => $owner->getEmail()
            ])
            ->getQuery()
            ->getOneOrNullResult();

        if ($user){

            if ($user->getGithubId() === null){
                $user->setGithubId($owner->getId());

                $em->persist($user);
                $em->flush();
            }

            return $user;
        }

        $user = (new User())
            ->setRoles(['ROLE_USER'])
            ->setGithubId($owner->getId())
            ->setEmail($owner->getEmail());

        $em->persist($user);
        $em->flush();

        return $user;
    }

    /**
     * @param FacebookUser $owner
     * @return User
     * @throws NonUniqueResultException
     */
    public function findOrCreateFromFacebookOauth(FacebookUser $owner): User
    {
        $em = $this->getEntityManager();

        /** @var User|null $user */
        $user = $this->createQueryBuilder('u')
            ->where('u.facebookId = :facebookId')
            ->orWhere('u.email = :email')
            ->setParameters([
                'facebookId' => $owner->getId(),
                'email' => $owner->getEmail()
            ])
            ->getQuery()
            ->getOneOrNullResult();

        if ($user){

            if ($user->getFacebookId() === null){
                $user->setFacebookId($owner->getId());

                $em->persist($user);
                $em->flush();
            }

            return $user;
        }

        $user = (new User())
            ->setRoles(['ROLE_USER'])
            ->setFacebookId($owner->getId())
            ->setEmail($owner->getEmail());

        $em->persist($user);
        $em->flush();

        return $user;
    }

    /**
     * @param GoogleUser $owner
     * @return User
     * @throws NonUniqueResultException
     */
    public function findOrCreateFromGoogleOauth(GoogleUser $owner): User
    {
        $em = $this->getEntityManager();

        /** @var User|null $user */
        $user = $this->createQueryBuilder('u')
            ->where('u.googleId = :googleId')
            ->orWhere('u.email = :email')
            ->setParameters([
                'googleId' => $owner->getId(),
                'email' => $owner->getEmail()
            ])
            ->getQuery()
            ->getOneOrNullResult();

        if ($user){

            if ($user->getGoogleId() === null){
                $user->setGoogleId($owner->getId());

                $em->persist($user);
                $em->flush();
            }

            return $user;
        }

        $user = (new User())
            ->setRoles(['ROLE_USER'])
            ->setGoogleId($owner->getId())
            ->setEmail($owner->getEmail());

        $em->persist($user);
        $em->flush();

        return $user;
    }

    /**
     * @param InstagramResourceOwner $instagramUser
     * @return User|null
     * @throws NonUniqueResultException
     */
    public function findOrCreateFromInstagramOauth(InstagramResourceOwner $instagramUser): ?User
    {
        $em = $this->getEntityManager();

        /** @var User|null $user */
        $user = $this->createQueryBuilder('u')
            ->where('u.instagramId = :instagramId')
            ->orWhere('u.email = :email')
            ->setParameters([
                'instagramId' => $instagramUser->getId(),
                'email' => $instagramUser->getNickname()
            ])
            ->getQuery()
            ->getOneOrNullResult();

        if ($user){

            if ($user->getGoogleId() === null){
                $user->setGoogleId($instagramUser->getId());

                $em->persist($user);
                $em->flush();
            }

            return $user;
        }

        $user = (new User())
            ->setRoles(['ROLE_USER'])
            ->setInstagramId($instagramUser->getId())
            ->setEmail($instagramUser->getNickname());

        $em->persist($user);
        $em->flush();

        return $user;
    }
}
