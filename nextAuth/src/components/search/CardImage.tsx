"use client"

import { useState } from "react";

export default function CardImage({ card }: { card: any }) {
  const [imageError, setImageError] = useState(false);

  if (!card) {
    return (
      <div className="empty-card">
        <div className="empty-card-content">
          <p>Select a card to view details</p>
        </div>
      </div>
    );
  }

  // Construct the image URL based on card properties
  const imageUrl = card.imageUrl || 
    `https://api.scryfall.com/cards/${card.setCode}/${card.collectorNumber}?format=image`;

  // Handle fallback if the main image URL fails
  const handleImageError = () => {
    setImageError(true);
  };

  return (
    <div className="card-image-wrapper">
      {!imageError ? (
        <img 
          src={imageUrl} 
          alt={card.name} 
          className="card-image"
          onError={handleImageError}
        />
      ) : (
        <div className="fallback-card">
          <div className="fallback-card-content">
            <div className="fallback-card-name">{card.name}</div>
            <div className="fallback-card-set">{card.setName}</div>
            <div className="fallback-card-number">#{card.collectorNumber}</div>
            {card.foil && <div className="fallback-card-foil">FOIL</div>}
          </div>
        </div>
      )}
    </div>
  );
}