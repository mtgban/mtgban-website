'use client'

import React, { forwardRef, HTMLAttributes } from 'react'
import { cn } from '@/lib/helpers'

interface CardProps extends HTMLAttributes<HTMLDivElement> {}

const Card = forwardRef<HTMLDivElement, CardProps>(({ className, ...props}, ref) => {
    return (
        <div
        ref={ref}
        className={cn(
            
        )}
        {...props}
        />
    )
})

Card.displayName = 'Card'

export default Card
