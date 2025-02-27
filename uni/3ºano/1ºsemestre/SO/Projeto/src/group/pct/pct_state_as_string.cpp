/*
 *  \author ...
 */

#include "somm22.h"
#include "pct_module.h"

namespace somm22
{

    namespace group 
    {

// ================================================================================== //

        const char *pctStateAsString(ProcessState state)
        {
            soProbe(291, "%s(\"%u\")\n", __func__, state);

            switch(state) {
                case TO_COME:
                    return "TO_COME";
                case RUNNING:
                    return "RUNNING";
                case SWAPPED:
                    return "SWAPPED";
                case FINISHED:
                    return "FINISHED";
                case DISCARDED:
                    return "DISCARDED";
                default:
                    return "UNKNOWN";
            }
        }

// ================================================================================== //

    } // end of namespace group

} // end of namespace somm22

