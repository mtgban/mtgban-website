import React, { useState } from 'react';
import { useCard, useCardPrices, useTrendData } from '../../hooks/useMtgBan';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

interface CardDetailProps {
  cardId: string;
}

const CardDetail = ({ cardId }: CardDetailProps) => {
  const [selectedPricePeriod, setSelectedPricePeriod] = useState<'week' | 'month' | 'year' | 'all'>('month');
  
  // Fetch card data
  const { 
    data: card, 
    loading: cardLoading, 
    error: cardError 
  } = useCard(cardId);
  
  // Fetch price data
  const { 
    data: prices, 
    loading: pricesLoading, 
    error: pricesError 
  } = useCardPrices(cardId);
  
  // Fetch price trend data
  const { 
    data: trendData, 
    loading: trendLoading 
  } = useTrendData(cardId, selectedPricePeriod);
  
  // Loading state
  if (cardLoading) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }
  
  // Error state
  if (cardError || !card) {
    return (
      <div className="container mx-auto p-4">
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Error loading card: {cardError || "Card not found"}
        </div>
      </div>
    );
  }
  
  // Group prices by source type
  const retailPrices = prices?.filter(p => 
    !p.source.toLowerCase().includes('buylist')
  ) || [];
  
  const buylistPrices = prices?.filter(p => 
    p.source.toLowerCase().includes('buylist')
  ) || [];
  
  // Format trend data for chart
  const formattedTrendData = trendData?.map(point => ({
    date: new Date(point.date).toLocaleDateString(),
    [point.source]: point.price,
  })) || [];
  
  // Group trend data by date
  const groupedTrendData = formattedTrendData.reduce((acc, curr) => {
    const existingIndex = acc.findIndex(item => item.date === curr.date);
    if (existingIndex >= 0) {
      acc[existingIndex] = { ...acc[existingIndex], ...curr };
    } else {
      acc.push(curr);
    }
    return acc;
  }, [] as any[]);
  
  // Sort trend data by date
  groupedTrendData.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
  
  // Get unique sources for chart colors
  const trendSources = Array.from(
    new Set(trendData?.map(point => point.source) || [])
  );
  
  // Chart colors
  const colors = [
    '#3B82F6', // blue-500
    '#EF4444', // red-500
    '#10B981', // green-500
    '#F59E0B', // amber-500
    '#8B5CF6', // violet-500
    '#EC4899', // pink-500
  ];
  
  return (
    <div className="container mx-auto p-4">
      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        {/* Card header */}
        <div className="relative bg-gradient-to-r from-blue-500 to-purple-600 p-6 text-white">
          <h1 className="text-3xl font-bold">{card.name}</h1>
          <div className="flex items-center mt-2">
            <span className="bg-black bg-opacity-30 rounded px-2 py-1 text-sm mr-2">
              {card.set_name} ({card.set_code})
            </span>
            <span className="bg-black bg-opacity-30 rounded px-2 py-1 text-sm mr-2">
              #{card.number}
            </span>
            <span className={`rounded px-2 py-1 text-sm text-white ${
              card.rarity === 'common' ? 'bg-gray-600' :
              card.rarity === 'uncommon' ? 'bg-blue-400' :
              card.rarity === 'rare' ? 'bg-yellow-500' :
              card.rarity === 'mythic' ? 'bg-red-500' :
              'bg-purple-500'
            }`}>
              {card.rarity.charAt(0).toUpperCase() + card.rarity.slice(1)}
            </span>
            {card.foil && (
              <span className="ml-2 rounded px-2 py-1 text-sm bg-gradient-to-r from-blue-400 to-purple-500">
                Foil
              </span>
            )}
            {card.etched && (
              <span className="ml-2 rounded px-2 py-1 text-sm bg-gradient-to-r from-gray-400 to-gray-600">
                Etched
              </span>
            )}
            {card.reserved && (
              <span className="ml-2 rounded px-2 py-1 text-sm bg-yellow-600">
                Reserved List
              </span>
            )}
          </div>
        </div>
        
        {/* Card content */}
        <div className="p-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Card image */}
            <div className="lg:col-span-1">
              {card.image_url ? (
                <div className="rounded overflow-hidden shadow-lg">
                  <img 
                    src={card.image_url} 
                    alt={card.name} 
                    className="w-full"
                  />
                </div>
              ) : (
                <div className="w-full h-96 bg-gray-200 flex items-center justify-center text-gray-500 rounded">
                  No Image Available
                </div>
              )}
              
              <div className="mt-4">
                <h3 className="text-lg font-semibold mb-2">Card Information</h3>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                  {card.identifiers && (
                    <>
                      {Object.entries(card.identifiers).map(([key, value]) => (
                        <React.Fragment key={key}>
                          <dt className="font-medium text-gray-500">{key}</dt>
                          <dd>{String(value)}</dd>
                        </React.Fragment>
                      ))}
                    </>
                  )}
                  {card.metadata && (
                    <>
                      {Object.entries(card.metadata).map(([key, value]) => {
                        // Skip arrays and objects in the display
                        if (typeof value !== 'object') {
                          return (
                            <React.Fragment key={key}>
                              <dt className="font-medium text-gray-500">
                                {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                              </dt>
                              <dd>{String(value)}</dd>
                            </React.Fragment>
                          );
                        }
                        return null;
                      })}
                    </>
                  )}
                </dl>
              </div>
              
              {/* External links */}
              {(card.stocks_url || card.identifiers?.scryfallId) && (
                <div className="mt-4">
                  <h3 className="text-lg font-semibold mb-2">External Links</h3>
                  <div className="space-y-2">
                    {card.stocks_url && (
                      <a 
                        href={card.stocks_url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="block px-4 py-2 bg-blue-100 text-blue-800 rounded hover:bg-blue-200"
                      >
                        View on MTG Stocks
                      </a>
                    )}
                    {card.identifiers?.scryfallId && (
                      <a 
                        href={`https://scryfall.com/card/${card.identifiers.scryfallId}`} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="block px-4 py-2 bg-purple-100 text-purple-800 rounded hover:bg-purple-200"
                      >
                        View on Scryfall
                      </a>
                    )}
                  </div>
                </div>
              )}
            </div>
            
            {/* Prices and chart */}
            <div className="lg:col-span-2">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Retail prices */}
                <div className="bg-white rounded-lg border p-4 shadow-sm">
                  <h3 className="text-lg font-semibold mb-3">Retail Prices</h3>
                  {pricesLoading ? (
                    <div className="flex justify-center py-4">
                      <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-blue-500"></div>
                    </div>
                  ) : pricesError ? (
                    <p className="text-red-500">Error loading prices</p>
                  ) : retailPrices.length === 0 ? (
                    <p className="text-gray-500">No retail prices available</p>
                  ) : (
                    <div className="space-y-2">
                      {retailPrices.map((price, index) => (
                        <div key={index} className="flex justify-between items-center py-1 border-b last:border-b-0">
                          <div>
                            <span className="font-medium">{price.source}</span>
                            {price.condition && price.condition !== 'NM' && (
                              <span className="ml-1 text-xs text-gray-500">({price.condition})</span>
                            )}
                          </div>
                          <div className="flex items-center">
                            <span className="font-bold">${price.price.toFixed(2)}</span>
                            {!price.in_stock && (
                              <span className="ml-2 px-1.5 py-0.5 text-xs bg-gray-200 text-gray-800 rounded">
                                Out of Stock
                              </span>
                            )}
                            {price.url && (
                              <a 
                                href={price.url} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="ml-2 text-blue-500 hover:text-blue-700"
                              >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                </svg>
                              </a>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                
                {/* Buylist prices */}
                <div className="bg-white rounded-lg border p-4 shadow-sm">
                  <h3 className="text-lg font-semibold mb-3">Buylist Prices</h3>
                  {pricesLoading ? (
                    <div className="flex justify-center py-4">
                      <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-blue-500"></div>
                    </div>
                  ) : pricesError ? (
                    <p className="text-red-500">Error loading prices</p>
                  ) : buylistPrices.length === 0 ? (
                    <p className="text-gray-500">No buylist prices available</p>
                  ) : (
                    <div className="space-y-2">
                      {buylistPrices.map((price, index) => (
                        <div key={index} className="flex justify-between items-center py-1 border-b last:border-b-0">
                          <div>
                            <span className="font-medium">{price.source}</span>
                            {price.condition && price.condition !== 'NM' && (
                              <span className="ml-1 text-xs text-gray-500">({price.condition})</span>
                            )}
                          </div>
                          <div className="flex items-center">
                            <span className="font-bold">${price.price.toFixed(2)}</span>
                            {price.quantity && (
                              <span className="ml-2 px-1.5 py-0.5 text-xs bg-green-100 text-green-800 rounded">
                                Qty: {price.quantity}
                              </span>
                            )}
                            {price.url && (
                              <a 
                                href={price.url} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="ml-2 text-blue-500 hover:text-blue-700"
                              >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                </svg>
                              </a>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              
              {/* Price trend chart */}
              <div className="mt-6 bg-white rounded-lg border p-4 shadow-sm">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-lg font-semibold">Price History</h3>
                  <div className="flex space-x-2">
                    <button 
                      onClick={() => setSelectedPricePeriod('week')}
                      className={`px-3 py-1 text-sm rounded ${
                        selectedPricePeriod === 'week' 
                          ? 'bg-blue-500 text-white' 
                          : 'bg-gray-200 hover:bg-gray-300'
                      }`}
                    >
                      Week
                    </button>
                    <button 
                      onClick={() => setSelectedPricePeriod('month')}
                      className={`px-3 py-1 text-sm rounded ${
                        selectedPricePeriod === 'month' 
                          ? 'bg-blue-500 text-white' 
                          : 'bg-gray-200 hover:bg-gray-300'
                      }`}
                    >
                      Month
                    </button>
                    <button 
                      onClick={() => setSelectedPricePeriod('year')}
                      className={`px-3 py-1 text-sm rounded ${
                        selectedPricePeriod === 'year' 
                          ? 'bg-blue-500 text-white' 
                          : 'bg-gray-200 hover:bg-gray-300'
                      }`}
                    >
                      Year
                    </button>
                    <button 
                      onClick={() => setSelectedPricePeriod('all')}
                      className={`px-3 py-1 text-sm rounded ${
                        selectedPricePeriod === 'all' 
                          ? 'bg-blue-500 text-white' 
                          : 'bg-gray-200 hover:bg-gray-300'
                      }`}
                    >
                      All
                    </button>
                  </div>
                </div>
                
                {trendLoading ? (
                  <div className="flex justify-center py-12">
                    <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
                  </div>
                ) : groupedTrendData.length === 0 ? (
                  <div className="text-center py-12 text-gray-500">
                    No price history data available
                  </div>
                ) : (
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart
                        data={groupedTrendData}
                        margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis 
                          dataKey="date" 
                          tick={{ fontSize: 12 }}
                          interval={groupedTrendData.length > 30 ? 2 : 0}
                        />
                        <YAxis 
                          tickFormatter={(tick) => `$${tick}`}
                          domain={['dataMin - 1', 'dataMax + 1']}
                        />
                        <Tooltip 
                          formatter={(value) => [`$${Number(value).toFixed(2)}`, '']}
                          labelFormatter={(label) => `Date: ${label}`}
                        />
                        <Legend />
                        {trendSources.map((source, index) => (
                          <Line
                            key={source}
                            type="monotone"
                            dataKey={source}
                            stroke={colors[index % colors.length]}
                            activeDot={{ r: 8 }}
                            name={source}
                          />
                        ))}
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CardDetail;