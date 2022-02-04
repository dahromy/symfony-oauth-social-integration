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
     * @param FacebookUser|GithubResourceOwner|GoogleUser|InstagramResourceOwner $socialUser
     * @param string $service
     * @return User|null
     * @throws NonUniqueResultException
     */
    public function findOrCreateFromOauth($socialUser, string $service): ?User
    {
        $em = $this->getEntityManager();
        $_service = ucfirst($service);
        $getMethod = "get{$_service}Id";
        $setMethod = "set{$_service}Id";

        $qb = $this->createQueryBuilder('u')
            ->where("u.{$service}Id = :serviceId")
            ->orWhere('u.email = :email')
            ->setParameter('serviceId', $socialUser->getId());

        if (method_exists($socialUser, 'getNickName')){
            $qb->setParameter('email', $socialUser->getNickname());
        }else{
            $qb->setParameter('email', $socialUser->getEmail());
        }

        /** @var User|null $user */
        $user = $qb
            ->getQuery()
            ->getOneOrNullResult()
        ;

        if ($user){
            if ($user->$getMethod() === null){
                $user->$setMethod($socialUser->getId());

                $em->persist($user);
                $em->flush();
            }

            return $user;
        }

        $user = new User();

        $user
            ->setRoles(['ROLE_USER'])
            ->$setMethod($socialUser->getId());

        if (method_exists($socialUser, 'getNickName')){
            $user->setEmail($socialUser->getNickname());
        }else{
            $user->setEmail($socialUser->getEmail());
        }

        $em->persist($user);
        $em->flush();

        return $user;
    }
}
