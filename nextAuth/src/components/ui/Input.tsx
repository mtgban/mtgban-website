'use client'

import React, { forwardRef, useRef, InputHTMLAttributes } from 'react'
import { mergeRefs } from 'react-merge-refs'
import { cn } from '@/lib/helpers'
interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  className?: string
}

const Input = forwardRef<HTMLInputElement, InputProps>(({ className, ...props}, ref) => {
  const inputRef = useRef<HTMLInputElement>(null)

  return (
    <div className="relative">
      <input
        className={cn(
          'peer h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background transition-all file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
        )}
        ref={mergeRefs([inputRef, ref])}
        {...props}
        />
    </div>
  )
})

Input.displayName = 'Input'

export default Input
