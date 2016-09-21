/*  CTimer.cpp
 * - Class for time and related operations
 *
 * July 2008
 * @author : Midhun Harikumar
 * (c) Centrum inc Software Solutions
 *
 * $ Version 0.4.1
 **/

# include <dos>
# include <time>
# include <stdio>

namespace CTimerBlock{

	class CTimer
   {
	protected:
   	struct time tKeeper;
   	unsigned char sFormattedTime[32];

   public:
   	CTimer();  /*Initialize with the currenty system time*/
      CTimer(struct time);
      unsigned char * getFormattedTimeString();
      unsigned int getIntermediateTime();

      CTimer operator - (CTimer);
   };

   // End Clas Definition
   ///////////////////////////////////

   CTimer :: CTimer()									// 0-arg constructor
   { gettime(&tKeeper);sFormattedTime[0] = 0;}

   CTimer :: CTimer(struct time t)
   { tKeeper = t;}

   unsigned int CTimer :: getIntermediateTime()	// Returns intermediate time value for comparosins
   {
   	return (tKeeper.ti_hund + (tKeeper.ti_sec*100) + (tKeeper.ti_min*10000) + (tKeeper.ti_hour*1000000)) ;
   }

   unsigned char* CTimer :: getFormattedTimeString() // Returns formatted time as string
   {
 	   sprintf(	sFormattedTime,
      			" [ %2d : %02d : %02d.%02d ]",
               tKeeper.ti_hour,
               tKeeper.ti_min,
               tKeeper.ti_sec,
               tKeeper.ti_hund);
      return sFormattedTime;
   }

   CTimer CTimer :: operator - (CTimer t2)
   {
   	unsigned int nDuration = getIntermediateTime() - t2.getIntermediateTime();
		struct time td;

      td.ti_hund = nDuration%100; nDuration /= 100; // now set td with duration
      td.ti_sec  = nDuration%100; nDuration /= 100;
      td.ti_min  = nDuration%100; nDuration /= 100;
      td.ti_hour = nDuration%100; nDuration /= 100;

      return CTimer(td);
   }

}
/*End of Namespace*/