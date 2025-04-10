'use client';
import React, { forwardRef, useRef, ButtonHTMLAttributes } from 'react';
import { mergeRefs } from 'react-merge-refs';
import LoadingDots from '@/components/ui/LoadingDots';

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'slim' | 'flat' | 'primary' | 'secondary' | 'accent';
  active?: boolean;
  width?: number;
  loading?: boolean;
  Component?: React.ComponentType;
}

const Button = forwardRef<HTMLButtonElement, Props>((props, buttonRef) => {
  const {
    className,
    variant = 'primary',
    children,
    active,
    width,
    loading = false,
    disabled = false,
    style = {},
    Component = 'button',
    ...rest
  } = props;
  
  const ref = useRef(null);
  
  // Define our button classes based on variant and state
  let buttonClass = 'btn';
  
  // Add variant-specific classes
  if (variant === 'slim') {
    buttonClass += ' btn-secondary';
  } else if (variant === 'flat') {
    buttonClass += ' btn-primary';
  } else {
    buttonClass += ` btn-${variant}`;
  }
  
  // Add loading and disabled classes
  if (loading) {
    buttonClass += ' disabled';
  }
  
  if (disabled) {
    buttonClass += ' disabled';
  }
  
  // Add any additional classes
  if (className) {
    buttonClass += ` ${className}`;
  }

  return (
    <Component
      aria-pressed={active}
      data-variant={variant}
      ref={mergeRefs([ref, buttonRef])}
      className={buttonClass}
      disabled={disabled}
      style={{
        width: width ? `${width}px` : undefined,
        ...style
      }}
      {...rest}
    >
      {children}
      {loading && (
        <span className="spinner" style={{ marginLeft: '0.5rem' }}></span>
      )}
    </Component>
  );
});

Button.displayName = 'Button';
export default Button;