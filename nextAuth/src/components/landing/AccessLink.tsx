import AuthLink from '@/components/auth/AuthLink';

const AccessLink = () => {
  return (
    <AuthLink
      href="/pricing/details"
      className="
        pointer-events-auto 
        outline-none 
        focus:outline-none 
        focus-visible:outline-none 
        active:outline-none
        ring-0
        focus:ring-0
        focus-visible:ring-0
      "
    >
      <h1 className="
        text-3xl 
        font-extrabold 
        text-center 
        sm:text-5xl 
        relative 
        inline-block 
        outline-none 
        focus:outline-none 
        focus-visible:outline-none
        ring-0
        focus:ring-0
        focus-visible:ring-0
      ">
        <span
          className="
            relative
            inline-block
            transition-all
            duration-300
            outline-none
            focus:outline-none
            focus-visible:outline-none
            ring-0
            focus:ring-0
            focus-visible:ring-0
            before:content-['GAIN_ACCESS']
            before:absolute
            before:inset-0
            before:bg-gradient-to-t
            before:from-[#ff4000f5]
            before:to-[#ff0000f4]
            before:bg-clip-text
            before:text-transparent
            after:content-['GAIN_ACCESS']
            after:absolute
            after:inset-0
            after:text-transparent
            after:transition-all
            after:duration-300
            after:[text-stroke:0.5px_transparent]
            after:[-webkit-text-stroke:0.5px_transparent]
            hover:after:[text-stroke:0.5px_#FFD700]
            hover:after:[-webkit-text-stroke:0.5px_#FFD700]
            hover:after:drop-shadow-[0_0_1px_rgba(255,215,0,0.7)]
          "
        >
          <span className="opacity-0 outline-none focus:outline-none focus-visible:outline-none">GAIN ACCESS</span>
        </span>
      </h1>
    </AuthLink>
  );
};

export default AccessLink;