import Head from 'next/head';
import { useRouter } from 'next/router';
import SignupForm from '@/components/auth/SignupForm';

export default function SignupPage() {
  const router = useRouter();
  // Get redirectTo from client-side query params
  const redirectTo = router.query.redirectTo as string | undefined;
  
  return (
    <>
      <Head>
        <title>Sign Up | MTGBAN</title>
        <meta name="description" content="Create a new MTGBAN account" />
      </Head>
      
      <div className="auth-page">
        <SignupForm redirectTo={redirectTo} />
      </div>
    </>
  );
}