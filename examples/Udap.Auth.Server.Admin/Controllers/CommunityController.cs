#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Udap.Auth.Server.Admin.Services.DataBase;
using Udap.Common.Models;
using Udap.Server.Mappers;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Udap.Auth.Server.Admin.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CommunityController : ControllerBase
    {
        ICommunityService _communityService;
        private readonly ILogger<CommunityController> _logger;

        public CommunityController(ICommunityService communityService, ILogger<CommunityController> logger)
        {
            _communityService = communityService;
            _logger = logger;
        }

        // GET: api/<CommunityController>
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Community>>> GetAsync(CancellationToken token)
        {
            var entitities = await _communityService.Get(token);
            
            if (!entitities.Any())
            {
                return NotFound();
            }
            
            var communities = entitities.Select(e => e.ToModel());

            return Ok(communities);
        }

        // GET api/<CommunityController>/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Community>> Get(int id, CancellationToken token)
        {
            var entity = await _communityService.Get(id, token);

            if (entity == null)
            {
                return NotFound();
            }
            var community = entity.ToModel();

            return Ok(community);
        }

        // POST api/<CommunityController>
        [HttpPost]
        public async Task<ActionResult<Community>> Post([FromBody] Community value, CancellationToken token)
        {
            try
            {
                var result = await _communityService.Add(value.ToEntity(), token).ConfigureAwait(false);

                return Created(result.Id.ToString(), result.ToModel());
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Error calling {0}", nameof(Post));
                
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calling {0}", nameof(Get));
                throw;
            }
        }

        // PUT api/<CommunityController>/5
        [HttpPut("{id}")]
        public async Task<ActionResult> Put(int id, [FromBody] Community value, CancellationToken token)
        {
            try
            {
                await _communityService.Update(value.ToEntity(), token).ConfigureAwait(false);

                return NoContent(); // https://www.rfc-editor.org/rfc/rfc9110.html#name-204-no-content
                // Although... https://blog.ploeh.dk/2013/04/30/rest-lesson-learned-avoid-204-responses/
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Error calling {0}", nameof(Put));

                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calling {0}", nameof(Put));
                throw;
            }
        }

        // DELETE api/<CommunityController>/5
        [HttpDelete("{id}")]
        public async Task<ActionResult<bool>> Delete(int id, CancellationToken token)
        {
            var response = await _communityService.Delete(id, token);

            if (response)
            {
                return Ok();
            }

            return NotFound();
        }
    }
}