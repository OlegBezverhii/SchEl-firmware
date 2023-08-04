/* Ruben Santamarta - IOActive */
/* Rebuild VxWorks Symbol Table */

#include <idc.idc>



static main()
{

	 auto ea;
	 auto offset;
	 auto sName;
	 auto eaStart;
	 auto eaEnd;
	 

	// You'll need to adjust these values
	eaStart = 0x0031DEB4;
	  eaEnd = 0x00346B74;
	 
	 SetStatus(IDA_STATUS_WORK);
	 
	 ea = eaStart;
	 
	 while( ea < eaEnd) {
	 
	 	MakeDword( ea );
	
	 	offset = 0;
	 	
	 	if ( Dword( ea ) == 0x900 || Dword( ea ) == 0x500)
	 	{
	 	
	 		offset = 8;
	 	}
	 	else if( Dword( ea ) == 0x90000 || Dword( ea ) == 0x50000 )
	 	{
	 	
	 		offset = 0xc;
	 	}
	 	
	 	if( offset )
	 	{

	 		MakeStr( Dword( ea - offset ), BADADDR);
	 		
	 		sName = GetString( Dword( ea - offset ), -1, ASCSTR_C ) ; 
	 	 	if ( sName )
	 	 	{
	 	 		if( Dword( ea ) == 0x500 || Dword( ea ) == 0x50000)
	 	 		{
	 	 	    	if (  GetFunctionName( Dword( ea - offset + 4) ) == "" )
	 	 	    	{
	 	 	    		MakeCode( Dword( ea - offset + 4) );
	 					MakeFunction( Dword( ea - offset + 4), BADADDR );	
	 	 	    	}
	 	 	    }
	 	 		MakeName( Dword( ea - offset + 4 ), sName );
	 	 		
	 	 	}
	 	}
	 	ea = ea + 4;
	 	 	 	
	 }

	 
	 SetStatus(IDA_STATUS_READY);
}